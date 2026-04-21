#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "detection.h"
#include "logger.h"
#include "control.h"

#define MAX_TRACKED_PROCESSES 8192
#define REASON_APPEND_GUARD 32
#define LOG_NAME_CHARS 128
#define LOG_REASON_CHARS 384

typedef struct {
    int pid;
    int seen_this_cycle;
    long last_memory_kb;
    int last_fd_count;
    unsigned int sustained_alerts;
} ProcessHistory;

static int contains_demo_signature(const char *value) {
    static const char *signatures[] = {
        "sim_mem",
        "sim_fd",
        "sim_fork",
        "sim_cpu",
        "sim_socket",
        "sim_combo"
    };
    size_t i;

    if (!value || !*value) {
        return 0;
    }

    for (i = 0; i < sizeof(signatures) / sizeof(signatures[0]); i++) {
        if (strstr(value, signatures[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

static DetectionRules rules = {
    500000L, /* max_memory_kb */
    128,     /* max_fd_count */
    32,      /* max_socket_count */
    64,      /* max_threads */
    85.0,    /* max_cpu_percent */
    128000L, /* max_memory_growth_kb */
    32,      /* max_fd_growth */
    24,      /* max_children_per_ppid */
    40,      /* min_alert_score */
    2,       /* alert_persistence_cycles */
    2,       /* monitor_interval_seconds */
    131072L, /* sandbox_memory_kb */
    64,      /* sandbox_fd_limit */
    15,      /* sandbox_cpu_seconds */
    8,       /* sandbox_eval_seconds */
    0,       /* sandbox_promote_after_clean */
    1500,    /* terminate_grace_ms */
    0,       /* allow_cross_uid_action */
    ACTION_MODE_PAUSE
};

static ProcessHistory history[MAX_TRACKED_PROCESSES];
static size_t history_count = 0;

static char *trim_whitespace(char *value) {
    char *end;

    while (*value && isspace((unsigned char) *value)) {
        value++;
    }

    if (*value == '\0') {
        return value;
    }

    end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char) *end)) {
        *end = '\0';
        end--;
    }

    return value;
}

static void append_reason(char *dest, size_t size, const char *reason) {
    size_t current_len;

    if (!reason || !*reason || size == 0) {
        return;
    }

    current_len = strlen(dest);
    if (current_len > 0 && current_len + REASON_APPEND_GUARD < size) {
        strncat(dest, "; ", size - strlen(dest) - 1);
    }

    strncat(dest, reason, size - strlen(dest) - 1);
}

static int find_history_index(int pid) {
    size_t i;

    for (i = 0; i < history_count; i++) {
        if (history[i].pid == pid) {
            return (int) i;
        }
    }

    return -1;
}

static void remove_history_index(size_t index) {
    if (index >= history_count) {
        return;
    }

    history[index] = history[history_count - 1];
    history_count--;
}

static ActionMode parse_action_mode(const char *value) {
    if (strcmp(value, "terminate") == 0) {
        return ACTION_MODE_TERMINATE;
    }
    if (strcmp(value, "kill") == 0) {
        return ACTION_MODE_KILL;
    }
    return ACTION_MODE_PAUSE;
}

/* Load thresholds and policy flags from conf/rules.conf with safe defaults. */
void load_rules(void) {
    FILE *fp = fopen("conf/rules.conf", "r");

    if (!fp) {
        printf("[WARN] Could not open conf/rules.conf. Using built-in safe defaults.\n");
        return;
    }

    while (!feof(fp)) {
        char line[256];
        char *trimmed;

        if (!fgets(line, sizeof(line), fp)) {
            break;
        }

        trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#') {
            continue;
        }

        if (strncmp(trimmed, "MAX_MEMORY_KB=", 14) == 0) {
            rules.max_memory_kb = strtol(trimmed + 14, NULL, 10);
        } else if (strncmp(trimmed, "MAX_FD_COUNT=", 13) == 0) {
            rules.max_fd_count = (int) strtol(trimmed + 13, NULL, 10);
        } else if (strncmp(trimmed, "MAX_SOCKET_COUNT=", 17) == 0) {
            rules.max_socket_count = (int) strtol(trimmed + 17, NULL, 10);
        } else if (strncmp(trimmed, "MAX_THREADS=", 12) == 0) {
            rules.max_threads = (int) strtol(trimmed + 12, NULL, 10);
        } else if (strncmp(trimmed, "MAX_CPU_PERCENT=", 16) == 0) {
            rules.max_cpu_percent = strtod(trimmed + 16, NULL);
        } else if (strncmp(trimmed, "MAX_MEMORY_GROWTH_KB=", 21) == 0) {
            rules.max_memory_growth_kb = strtol(trimmed + 21, NULL, 10);
        } else if (strncmp(trimmed, "MAX_FD_GROWTH=", 14) == 0) {
            rules.max_fd_growth = (int) strtol(trimmed + 14, NULL, 10);
        } else if (strncmp(trimmed, "MAX_CHILDREN_PER_PPID=", 22) == 0) {
            rules.max_children_per_ppid = (int) strtol(trimmed + 22, NULL, 10);
        } else if (strncmp(trimmed, "MIN_ALERT_SCORE=", 16) == 0) {
            rules.min_alert_score = (int) strtol(trimmed + 16, NULL, 10);
        } else if (strncmp(trimmed, "ALERT_PERSISTENCE_CYCLES=", 25) == 0) {
            rules.alert_persistence_cycles = (int) strtol(trimmed + 25, NULL, 10);
        } else if (strncmp(trimmed, "MONITOR_INTERVAL_SECONDS=", 25) == 0) {
            rules.monitor_interval_seconds = (int) strtol(trimmed + 25, NULL, 10);
        } else if (strncmp(trimmed, "SANDBOX_MEMORY_KB=", 18) == 0) {
            rules.sandbox_memory_kb = strtol(trimmed + 18, NULL, 10);
        } else if (strncmp(trimmed, "SANDBOX_FD_LIMIT=", 17) == 0) {
            rules.sandbox_fd_limit = (int) strtol(trimmed + 17, NULL, 10);
        } else if (strncmp(trimmed, "SANDBOX_CPU_SECONDS=", 20) == 0) {
            rules.sandbox_cpu_seconds = (int) strtol(trimmed + 20, NULL, 10);
        } else if (strncmp(trimmed, "SANDBOX_EVAL_SECONDS=", 21) == 0) {
            rules.sandbox_eval_seconds = (int) strtol(trimmed + 21, NULL, 10);
        } else if (strncmp(trimmed, "SANDBOX_PROMOTE_AFTER_CLEAN=", 28) == 0) {
            rules.sandbox_promote_after_clean = (int) strtol(trimmed + 28, NULL, 10);
        } else if (strncmp(trimmed, "TERMINATE_GRACE_MS=", 19) == 0) {
            rules.terminate_grace_ms = (int) strtol(trimmed + 19, NULL, 10);
        } else if (strncmp(trimmed, "ALLOW_CROSS_UID_ACTION=", 23) == 0) {
            rules.allow_cross_uid_action = (int) strtol(trimmed + 23, NULL, 10);
        } else if (strncmp(trimmed, "ACTION_MODE=", 12) == 0) {
            rules.action_mode = parse_action_mode(trimmed + 12);
        }
    }

    fclose(fp);

    printf("[OK] Rules loaded: mem=%ldkB fd=%d sockets=%d threads=%d cpu=%.1f%% score>=%d action=%d\n",
           rules.max_memory_kb,
           rules.max_fd_count,
           rules.max_socket_count,
           rules.max_threads,
           rules.max_cpu_percent,
           rules.min_alert_score,
           (int) rules.action_mode);
}

const DetectionRules *get_rules(void) {
    return &rules;
}

/* Mark tracked processes unseen before the next monitoring pass starts. */
void begin_detection_cycle(void) {
    size_t i;

    for (i = 0; i < history_count; i++) {
        history[i].seen_this_cycle = 0;
    }
}

/* Drop cached state for processes that disappeared between scans. */
void end_detection_cycle(void) {
    size_t i = 0;

    while (i < history_count) {
        if (!history[i].seen_this_cycle) {
            remove_history_index(i);
        } else {
            i++;
        }
    }
}

/* Score one process against the configured rules and trigger guarded response logic. */
void analyze_process(ProcessInfo *process) {
    int history_index;
    long memory_delta = 0;
    int fd_delta = 0;

    process->alerted = 0;
    process->memory_alert = 0;
    process->fd_alert = 0;
    process->socket_alert = 0;
    process->thread_alert = 0;
    process->cpu_alert = 0;
    process->growth_alert = 0;
    process->fork_alert = 0;
    process->alert_score = 0;
    process->action_taken = 0;
    process->protected_process = 0;
    process->sustained_alerts = 0;
    process->user_allowed = user_action_is_allowed(process->pid);
    process->manual_action_pending = 0;
    process->simulation_match = 0;
    process->action_label[0] = '\0';
    process->category[0] = '\0';
    process->alert_reason[0] = '\0';

    history_index = find_history_index(process->pid);
    if (history_index >= 0) {
        memory_delta = process->memory_kb - history[history_index].last_memory_kb;
        fd_delta = process->fd_count - history[history_index].last_fd_count;
        process->memory_delta_kb = memory_delta;
    } else {
        process->memory_delta_kb = 0;
    }

    if (process->memory_kb > rules.max_memory_kb) {
        char detail[96];
        process->memory_alert = 1;
        process->alert_score += 40;
        snprintf(detail, sizeof(detail), "memory %ldkB > %ldkB", process->memory_kb, rules.max_memory_kb);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (!process->fd_access_denied && process->fd_count > rules.max_fd_count) {
        char detail[96];
        process->fd_alert = 1;
        process->alert_score += 25;
        snprintf(detail, sizeof(detail), "fd %d > %d", process->fd_count, rules.max_fd_count);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (process->socket_count > rules.max_socket_count) {
        char detail[96];
        process->socket_alert = 1;
        process->alert_score += 20;
        snprintf(detail, sizeof(detail), "sockets %d > %d", process->socket_count, rules.max_socket_count);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (process->threads > rules.max_threads) {
        char detail[96];
        process->thread_alert = 1;
        process->alert_score += 20;
        snprintf(detail, sizeof(detail), "threads %d > %d", process->threads, rules.max_threads);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (process->cpu_percent > rules.max_cpu_percent) {
        char detail[96];
        process->cpu_alert = 1;
        process->alert_score += 20;
        snprintf(detail, sizeof(detail), "cpu %.1f%% > %.1f%%", process->cpu_percent, rules.max_cpu_percent);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (history_index >= 0 && memory_delta > rules.max_memory_growth_kb) {
        char detail[96];
        process->growth_alert = 1;
        process->alert_score += 20;
        snprintf(detail, sizeof(detail), "memory growth %+ldkB", memory_delta);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (history_index >= 0 && fd_delta > rules.max_fd_growth) {
        char detail[96];
        process->growth_alert = 1;
        process->alert_score += 15;
        snprintf(detail, sizeof(detail), "fd growth +%d", fd_delta);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (process->children_count > rules.max_children_per_ppid) {
        char detail[96];
        process->fork_alert = 1;
        process->alert_score += 35;
        snprintf(detail, sizeof(detail), "children %d > %d", process->children_count, rules.max_children_per_ppid);
        append_reason(process->alert_reason, sizeof(process->alert_reason), detail);
    }

    if (contains_demo_signature(process->name) || contains_demo_signature(process->cmdline)) {
        process->simulation_match = 1;
        process->alert_score += 60;
        snprintf(process->category, sizeof(process->category), "demo-malware");
        append_reason(process->alert_reason, sizeof(process->alert_reason), "matched bundled simulator signature");
    }

    process->alerted = process->alert_score >= rules.min_alert_score;

    if (history_index < 0 && history_count < MAX_TRACKED_PROCESSES) {
        history_index = (int) history_count;
        history[history_count].pid = process->pid;
        history[history_count].sustained_alerts = 0;
        history_count++;
    }

    if (history_index >= 0) {
        history[history_index].seen_this_cycle = 1;
        history[history_index].last_memory_kb = process->memory_kb;
        history[history_index].last_fd_count = process->fd_count;

        if (process->alerted) {
            history[history_index].sustained_alerts++;
        } else {
            history[history_index].sustained_alerts = 0;
        }

        process->sustained_alerts = (int) history[history_index].sustained_alerts;
    }

    if (!process->alerted) {
        return;
    }

    {
        char log_line[768];
        snprintf(log_line, sizeof(log_line),
                 "THREAT pid=%d name=%.*s score=%d sustained=%d reason=%.*s",
                 process->pid,
                 LOG_NAME_CHARS,
                 process->name,
                 process->alert_score,
                 process->sustained_alerts,
                 LOG_REASON_CHARS,
                 process->alert_reason);
        printf("[ALERT] %s\n", log_line);
        log_event(log_line);
    }

    if (process->sustained_alerts < rules.alert_persistence_cycles) {
        snprintf(process->action_label, sizeof(process->action_label), "OBSERVE");
        return;
    }

    if (process->user_allowed) {
        snprintf(process->action_label, sizeof(process->action_label), "USER_ALLOWED");
        return;
    }

    if (process->fork_alert) {
        enforce_mass_action(process->pid);
        snprintf(process->action_label, sizeof(process->action_label), "FAMILY_ACTION");
        process->action_taken = 1;
        return;
    }

    enforce_action(process);
}
