#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include "sandbox.h"
#include "detection.h"
#include "logger.h"

static pid_t active_child = -1;

static void sandbox_signal_handler(int signum) {
    if (active_child > 0) {
        (void) kill(-active_child, SIGTERM);
        usleep(200000);
        (void) kill(-active_child, SIGKILL);
    }
    _exit(128 + signum);
}

static int apply_limit(int resource, rlim_t value) {
    struct rlimit limit;

    limit.rlim_cur = value;
    limit.rlim_max = value;
    return setrlimit(resource, &limit);
}

static void prepare_sandbox_child(const DetectionRules *rules, char **argv) {
    int null_fd;

    (void) mkdir("sandbox_workspace", 0755);
    (void) chdir("sandbox_workspace");
    (void) setsid();

    if (apply_limit(RLIMIT_AS, (rlim_t) rules->sandbox_memory_kb * 1024) != 0 ||
        apply_limit(RLIMIT_NOFILE, (rlim_t) rules->sandbox_fd_limit) != 0 ||
        apply_limit(RLIMIT_CPU, (rlim_t) rules->sandbox_cpu_seconds) != 0 ||
        apply_limit(RLIMIT_CORE, 0) != 0 ||
        apply_limit(RLIMIT_FSIZE, 10 * 1024 * 1024) != 0) {
        perror("Failed to set sandbox limits");
        _exit(1);
    }

    null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        (void) dup2(null_fd, STDIN_FILENO);
        close(null_fd);
    }

    execvp(argv[0], argv);
    perror("Sandbox execution failed");
    _exit(1);
}

static int read_status_value(pid_t pid, const char *field, long *result) {
    char path[256];
    FILE *fp;
    char line[256];
    size_t field_len = strlen(field);

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, field, field_len) == 0) {
            long value = 0;
            if (sscanf(line + field_len, " %ld", &value) == 1) {
                *result = value;
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

static int count_fd_entries(pid_t pid) {
    char path[256];
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    dir = opendir(path);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static void force_stop_group(pid_t pgid, const char *reason) {
    char log_line[512];

    snprintf(log_line, sizeof(log_line), "SANDBOX BLOCKED pgid=%d reason=%s", (int) pgid, reason);
    printf("[SANDBOX] %s\n", log_line);
    log_event(log_line);

    (void) kill(-pgid, SIGTERM);
    usleep(300000);
    (void) kill(-pgid, SIGKILL);
}

static int evaluate_sandbox_process(pid_t pid, const DetectionRules *rules, char *reason, size_t reason_size, int *status) {
    time_t start_time = time(NULL);

    while (1) {
        long memory_kb = 0;
        long threads = 0;
        int fd_count = count_fd_entries(pid);
        pid_t wait_result = waitpid(pid, status, WNOHANG);

        if (wait_result == pid) {
            return 1;
        }

        if ((int) difftime(time(NULL), start_time) > rules->sandbox_eval_seconds) {
            snprintf(reason, reason_size, "sandbox evaluation timeout");
            return 0;
        }

        (void) read_status_value(pid, "VmRSS:", &memory_kb);
        (void) read_status_value(pid, "Threads:", &threads);

        if (memory_kb > rules->sandbox_memory_kb) {
            snprintf(reason, reason_size, "sandbox memory %ldkB > %ldkB", memory_kb, rules->sandbox_memory_kb);
            return 0;
        }

        if (fd_count > rules->sandbox_fd_limit) {
            snprintf(reason, reason_size, "sandbox fd %d > %d", fd_count, rules->sandbox_fd_limit);
            return 0;
        }

        if (threads > rules->max_threads) {
            snprintf(reason, reason_size, "sandbox threads %ld > %d", threads, rules->max_threads);
            return 0;
        }

        usleep(250000);
    }
}

static int run_supervised_child(char **argv, const DetectionRules *rules, int sandboxed) {
    pid_t pid = fork();
    int status = 0;
    char reason[256];

    if (pid < 0) {
        perror("Fork failed");
        return 0;
    }

    if (pid == 0) {
        if (sandboxed) {
            prepare_sandbox_child(rules, argv);
        } else {
            (void) setsid();
            execvp(argv[0], argv);
            perror("Host execution failed");
            _exit(1);
        }
    }

    active_child = pid;

    if (sandboxed && !evaluate_sandbox_process(pid, rules, reason, sizeof(reason), &status)) {
        force_stop_group(pid, reason);
        (void) waitpid(pid, &status, 0);
        active_child = -1;
        return 0;
    }

    if (!sandboxed && waitpid(pid, &status, 0) < 0) {
        perror("waitpid failed");
        active_child = -1;
        return 0;
    }

    active_child = -1;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 1;
    }

    if (WIFSIGNALED(status)) {
        char log_line[256];
        snprintf(log_line, sizeof(log_line), "PROCESS EXITED BY SIGNAL pid=%d signal=%d sandboxed=%d", (int) pid, WTERMSIG(status), sandboxed);
        log_event(log_line);
    }

    return 0;
}

/* Run a command in a supervised sandbox first and optionally promote it after a clean run. */
void run_in_sandbox(char **argv) {
    const DetectionRules *rules = get_rules();

    if (!argv || !argv[0]) {
        fprintf(stderr, "No command provided for sandbox execution.\n");
        return;
    }

    signal(SIGINT, sandbox_signal_handler);
    signal(SIGTERM, sandbox_signal_handler);

    printf("[SANDBOX] Evaluating `%s` inside restricted mode first.\n", argv[0]);
    printf("[SANDBOX] Limits: memory=%ldkB fd=%d cpu=%ds promote_after_clean=%d\n",
           rules->sandbox_memory_kb,
           rules->sandbox_fd_limit,
           rules->sandbox_cpu_seconds,
           rules->sandbox_promote_after_clean);

    if (!run_supervised_child(argv, rules, 1)) {
        printf("[SANDBOX] Command blocked or failed during sandbox review.\n");
        return;
    }

    printf("[SANDBOX] Command completed cleanly inside sandbox review.\n");

    if (!rules->sandbox_promote_after_clean) {
        printf("[SANDBOX] Promotion disabled by default to avoid running the same command twice.\n");
        printf("[SANDBOX] Set SANDBOX_PROMOTE_AFTER_CLEAN=1 in conf/rules.conf only for trusted, repeatable commands.\n");
        return;
    }

    printf("[SANDBOX] Promoting command to host execution.\n");
    if (!run_supervised_child(argv, rules, 0)) {
        printf("[SANDBOX] Host execution failed.\n");
    }
}
