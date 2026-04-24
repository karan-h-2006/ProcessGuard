#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include "control.h"
#include "detection.h"
#include "logger.h"

#define CONTROL_QUEUE_PATH "control_actions.jsonl"
#define MAX_ALLOWED_PIDS 1024

typedef struct {
    int pid;
    time_t allowed_at;
} AllowedPid;

static AllowedPid allowed_pids[MAX_ALLOWED_PIDS];
static size_t allowed_pid_count = 0;

static int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char) *str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

static int read_ppid_from_stat(int pid) {
    char path[256];
    FILE *fp;
    int file_pid;
    int ppid = 0;
    char comm[256];
    char state;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    if (fscanf(fp, "%d (%255[^)]) %c %d", &file_pid, comm, &state, &ppid) != 4) {
        ppid = 0;
    }

    fclose(fp);
    return ppid;
}

static int pid_exists(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

static char read_process_state_code(int pid) {
    char path[256];
    FILE *fp;
    char line[256];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return '\0';
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "State:", 6) == 0) {
            char state_code = '\0';

            if (sscanf(line, "State:\t%c", &state_code) == 1) {
                fclose(fp);
                return state_code;
            }
        }
    }

    fclose(fp);
    return '\0';
}

static int pid_is_live(int pid) {
    char state_code;

    if (!pid_exists(pid)) {
        return 0;
    }

    state_code = read_process_state_code(pid);
    if (state_code == 'Z' || state_code == 'X' || state_code == '\0') {
        return 0;
    }

    return 1;
}

static int find_allowed_pid_index(int pid) {
    size_t i;

    for (i = 0; i < allowed_pid_count; i++) {
        if (allowed_pids[i].pid == pid) {
            return (int) i;
        }
    }

    return -1;
}

static void mark_pid_allowed(int pid) {
    int index = find_allowed_pid_index(pid);

    if (index >= 0) {
        allowed_pids[index].allowed_at = time(NULL);
        return;
    }

    if (allowed_pid_count < MAX_ALLOWED_PIDS) {
        allowed_pids[allowed_pid_count].pid = pid;
        allowed_pids[allowed_pid_count].allowed_at = time(NULL);
        allowed_pid_count++;
    }
}

static void clear_allowed_pid(int pid) {
    int index = find_allowed_pid_index(pid);

    if (index < 0) {
        return;
    }

    allowed_pids[index] = allowed_pids[allowed_pid_count - 1];
    allowed_pid_count--;
}

int user_action_is_allowed(int pid) {
    int index = find_allowed_pid_index(pid);

    if (index < 0) {
        return 0;
    }

    if (!pid_is_live(pid)) {
        clear_allowed_pid(pid);
        return 0;
    }

    return 1;
}

static int is_protected_target(const ProcessInfo *process) {
    const DetectionRules *rules = get_rules();
    uid_t current_uid = geteuid();

    if (process->pid <= 100 || process->pid == getpid() || process->pid == getppid()) {
        return 1;
    }

    if (!rules->allow_cross_uid_action && process->uid != current_uid) {
        return 1;
    }

    return 0;
}

static int stop_or_kill_pid(int pid, ActionMode mode) {
    const DetectionRules *rules = get_rules();
    int signal_to_send = SIGSTOP;

    if (mode == ACTION_MODE_TERMINATE) {
        signal_to_send = SIGTERM;
    } else if (mode == ACTION_MODE_KILL) {
        signal_to_send = SIGKILL;
    }

    if (kill(pid, signal_to_send) != 0) {
        return 0;
    }

    if (mode == ACTION_MODE_KILL) {
        int waited_ms = 0;

        while (pid_is_live(pid) && waited_ms < rules->terminate_grace_ms) {
            usleep(100000);
            waited_ms += 100;
        }

        return !pid_is_live(pid);
    }

    if (mode == ACTION_MODE_TERMINATE) {
        int waited_ms = 0;

        while (pid_is_live(pid) && waited_ms < rules->terminate_grace_ms) {
            usleep(100000);
            waited_ms += 100;
        }

        if (pid_is_live(pid)) {
            (void) kill(pid, SIGKILL);
            waited_ms = 0;

            while (pid_is_live(pid) && waited_ms < rules->terminate_grace_ms) {
                usleep(100000);
                waited_ms += 100;
            }
        }

        return !pid_is_live(pid);
    }

    return 1;
}

static const char *action_label_from_mode(ActionMode mode) {
    switch (mode) {
        case ACTION_MODE_TERMINATE:
            return "TERMINATED";
        case ACTION_MODE_KILL:
            return "KILLED";
        case ACTION_MODE_PAUSE:
        default:
            return "PAUSED";
    }
}

/* Apply the configured policy to one suspicious process with ownership safeguards. */
void enforce_action(ProcessInfo *process) {
    char log_line[512];
    const DetectionRules *rules = get_rules();

    if (is_protected_target(process)) {
        process->protected_process = 1;
        snprintf(process->action_label, sizeof(process->action_label), "SKIPPED_PROTECTED");
        snprintf(log_line, sizeof(log_line),
                 "ACTION SKIPPED pid=%d name=%s uid=%u protected=1",
                 process->pid,
                 process->name,
                 process->uid);
        printf("[SAFEGUARD] %s\n", log_line);
        log_event(log_line);
        return;
    }

    if (stop_or_kill_pid(process->pid, rules->action_mode)) {
        process->action_taken = 1;
        snprintf(process->action_label, sizeof(process->action_label), "%s", action_label_from_mode(rules->action_mode));
        snprintf(log_line, sizeof(log_line),
                 "ACTION pid=%d name=%s result=%s score=%d",
                 process->pid,
                 process->name,
                 process->action_label,
                 process->alert_score);
        printf("[ACTION] %s\n", log_line);
        log_event(log_line);
        return;
    }

    snprintf(process->action_label, sizeof(process->action_label), "ACTION_FAILED");
    snprintf(log_line, sizeof(log_line),
             "ACTION FAILED pid=%d name=%s errno=%d (%s)",
             process->pid,
             process->name,
             errno,
             strerror(errno));
    printf("[ERROR] %s\n", log_line);
    log_event(log_line);
}

static UserAction parse_user_action(const char *value) {
    if (strcmp(value, "allow") == 0 || strcmp(value, "continue") == 0 || strcmp(value, "resume") == 0) {
        return USER_ACTION_ALLOW;
    }
    if (strcmp(value, "pause") == 0) {
        return USER_ACTION_PAUSE;
    }
    if (strcmp(value, "terminate") == 0 || strcmp(value, "stop") == 0) {
        return USER_ACTION_TERMINATE;
    }
    if (strcmp(value, "kill") == 0) {
        return USER_ACTION_KILL;
    }
    return USER_ACTION_NONE;
}

static void apply_user_action(int pid, UserAction action) {
    char log_line[256];
    int success = 1;

    if (pid <= 0) {
        return;
    }

    switch (action) {
        case USER_ACTION_ALLOW:
            mark_pid_allowed(pid);
            success = kill(pid, SIGCONT) == 0;
            snprintf(log_line, sizeof(log_line), "USER ACTION pid=%d action=ALLOW success=%d", pid, success);
            break;
        case USER_ACTION_PAUSE:
            clear_allowed_pid(pid);
            success = kill(pid, SIGSTOP) == 0;
            snprintf(log_line, sizeof(log_line), "USER ACTION pid=%d action=PAUSE success=%d", pid, success);
            break;
        case USER_ACTION_TERMINATE:
            clear_allowed_pid(pid);
            success = stop_or_kill_pid(pid, ACTION_MODE_TERMINATE);
            snprintf(log_line, sizeof(log_line), "USER ACTION pid=%d action=TERMINATE success=%d", pid, success);
            break;
        case USER_ACTION_KILL:
            clear_allowed_pid(pid);
            success = stop_or_kill_pid(pid, ACTION_MODE_KILL);
            snprintf(log_line, sizeof(log_line), "USER ACTION pid=%d action=KILL success=%d", pid, success);
            break;
        case USER_ACTION_NONE:
        default:
            return;
    }

    printf(success ? "[ACTION] %s\n" : "[ERROR] %s\n", log_line);
    log_event(log_line);
}

void process_control_queue(void) {
    FILE *fp = fopen(CONTROL_QUEUE_PATH, "r");
    char line[256];

    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        int pid = 0;
        char action_name[32];

        if (sscanf(line, "%d %31s", &pid, action_name) == 2) {
            apply_user_action(pid, parse_user_action(action_name));
        }
    }

    fclose(fp);
    fp = fopen(CONTROL_QUEUE_PATH, "w");
    if (fp) {
        fclose(fp);
    }
}

/* Apply the same enforcement mode to a fork-heavy parent and its visible children. */
void enforce_mass_action(int ppid) {
    DIR *dir;
    struct dirent *entry;
    int affected = 0;
    char log_line[256];
    ProcessInfo pseudo_process;

    memset(&pseudo_process, 0, sizeof(pseudo_process));
    pseudo_process.pid = ppid;
    pseudo_process.uid = geteuid();
    snprintf(pseudo_process.name, sizeof(pseudo_process.name), "process-family");

    if (ppid <= 100) {
        snprintf(log_line, sizeof(log_line), "MASS ACTION SKIPPED parent=%d protected=1", ppid);
        printf("[SAFEGUARD] %s\n", log_line);
        log_event(log_line);
        return;
    }

    dir = opendir("/proc");
    if (!dir) {
        perror("Failed to open /proc");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        int pid;
        int current_ppid;

        if (!is_numeric(entry->d_name)) {
            continue;
        }

        pid = atoi(entry->d_name);
        current_ppid = read_ppid_from_stat(pid);

        if (pid == ppid || current_ppid == ppid) {
            pseudo_process.pid = pid;
            if (!is_protected_target(&pseudo_process) && stop_or_kill_pid(pid, get_rules()->action_mode)) {
                affected++;
            }
        }
    }

    closedir(dir);

    snprintf(log_line, sizeof(log_line), "MASS ACTION parent=%d affected=%d", ppid, affected);
    printf("[ACTION] %s\n", log_line);
    log_event(log_line);
}
