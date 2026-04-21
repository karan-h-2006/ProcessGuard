#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "detection.h"
#include "logger.h"
#include "control.h"

long max_memory_kb = 500000; // Default fallback
int max_fd_count = 100;      // Default fallback
int max_children_per_ppid = 30; // Default fallback

typedef struct {
    int pid;
    int seen_this_cycle;
} AlertState;

typedef struct {
    int ppid;
    int count;
} PPIDFrequency;

#define MAX_TRACKED_ALERTS 4096
#define ALERT_NAME_LOG_CHARS 120
#define ALERT_REASON_LOG_CHARS 320
#define MAX_PPID_TRACKING 8192

static AlertState active_alerts[MAX_TRACKED_ALERTS];
static size_t active_alert_count = 0;
static PPIDFrequency ppid_freq[MAX_PPID_TRACKING];
static size_t ppid_freq_count = 0;

static char *trim_whitespace(char *str) {
    char *end;

    while (*str && isspace((unsigned char) *str)) {
        str++;
    }

    if (*str == '\0') {
        return str;
    }

    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) {
        *end = '\0';
        end--;
    }

    return str;
}

static int find_alert_state(int pid) {
    size_t i;

    for (i = 0; i < active_alert_count; i++) {
        if (active_alerts[i].pid == pid) {
            return (int) i;
        }
    }

    return -1;
}

static void remove_alert_state(size_t index) {
    if (index >= active_alert_count) {
        return;
    }

    active_alerts[index] = active_alerts[active_alert_count - 1];
    active_alert_count--;
}

static void update_ppid_frequency(int ppid) {
    size_t i;

    for (i = 0; i < ppid_freq_count; i++) {
        if (ppid_freq[i].ppid == ppid) {
            ppid_freq[i].count++;
            return;
        }
    }

    if (ppid_freq_count < MAX_PPID_TRACKING) {
        ppid_freq[ppid_freq_count].ppid = ppid;
        ppid_freq[ppid_freq_count].count = 1;
        ppid_freq_count++;
    }
}

static void reset_ppid_frequency() {
    ppid_freq_count = 0;
}

void load_rules() {
    FILE *fp = fopen("conf/rules.conf", "r");
    if (fp) {
        char line[256];

        // Read the file line by line to support multiple rules safely
        while (fgets(line, sizeof(line), fp)) {
            char *trimmed = trim_whitespace(line);

            if (*trimmed == '\0' || *trimmed == '#') {
                continue;
            }

            if (strncmp(trimmed, "MAX_MEMORY_KB=", 14) == 0) {
                max_memory_kb = strtol(trimmed + 14, NULL, 10);
            } else if (strncmp(trimmed, "MAX_FD_COUNT=", 13) == 0) {
                max_fd_count = (int) strtol(trimmed + 13, NULL, 10);
            } else if (strncmp(trimmed, "MAX_CHILDREN_PER_PPID=", 23) == 0) {
                max_children_per_ppid = (int) strtol(trimmed + 23, NULL, 10);
            }
        }
        fclose(fp);
        printf("[\033[0;32mOK\033[0m] Rules loaded: Mem Limit=%ld kB, FD Limit=%d, Max Children/PPID=%d\n", max_memory_kb, max_fd_count, max_children_per_ppid);
    } else {
        printf("[\033[0;33mWARN\033[0m] Could not open conf/rules.conf. Using defaults.\n");
    }
}

void begin_detection_cycle() {
    size_t i;

    for (i = 0; i < active_alert_count; i++) {
        active_alerts[i].seen_this_cycle = 0;
    }

    reset_ppid_frequency();
}

void end_detection_cycle() {
    size_t i = 0;

    while (i < active_alert_count) {
        if (!active_alerts[i].seen_this_cycle) {
            remove_alert_state(i);
        } else {
            i++;
        }
    }

    // Check for fork bomb patterns
    for (i = 0; i < ppid_freq_count; i++) {
        if (ppid_freq[i].count > max_children_per_ppid && ppid_freq[i].ppid > 100) {
            char fork_alert[512];
            snprintf(fork_alert, sizeof(fork_alert),
                     "Fork Bomb Pattern Detected! Parent PID %d has spawned %d children.",
                     ppid_freq[i].ppid, ppid_freq[i].count);

            printf("\033[0;31m>>> %s <<<\033[0m\n", fork_alert);
            log_event(fork_alert);
            enforce_mass_action(ppid_freq[i].ppid);
        }
    }
}

void analyze_process(ProcessInfo *process) {
    int cached_index;
    char alert_msg[512];

    process->memory_alert = process->memory_kb > max_memory_kb;
    process->fd_alert = process->fd_count > max_fd_count;
    process->alerted = process->memory_alert || process->fd_alert;
    process->action_taken = 0;
    process->alert_reason[0] = '\0';

    update_ppid_frequency(process->ppid);

    cached_index = find_alert_state(process->pid);

    if (!process->alerted) {
        if (cached_index >= 0) {
            remove_alert_state((size_t) cached_index);
        }
        return;
    }

    if (process->memory_alert && process->fd_alert) {
        snprintf(process->alert_reason, sizeof(process->alert_reason),
                 "Memory %ld kB > %ld kB and FD count %d > %d",
                 process->memory_kb, max_memory_kb, process->fd_count, max_fd_count);
    } else if (process->memory_alert) {
        snprintf(process->alert_reason, sizeof(process->alert_reason),
                 "Memory %ld kB > %ld kB",
                 process->memory_kb, max_memory_kb);
    } else {
        snprintf(process->alert_reason, sizeof(process->alert_reason),
                 "FD count %d > %d",
                 process->fd_count, max_fd_count);
    }

    if (cached_index >= 0) {
        active_alerts[cached_index].seen_this_cycle = 1;
        return;
    }

    if (active_alert_count < MAX_TRACKED_ALERTS) {
        active_alerts[active_alert_count].pid = process->pid;
        active_alerts[active_alert_count].seen_this_cycle = 1;
        active_alert_count++;
    }

    snprintf(alert_msg, sizeof(alert_msg), "Process %d (%.*s) %.*s",
             process->pid, ALERT_NAME_LOG_CHARS, process->name,
             ALERT_REASON_LOG_CHARS, process->alert_reason);

    printf("\033[0;31m>>> THREAT DETECTED: %s <<<\033[0m\n", alert_msg);
    log_event(alert_msg);
    process->action_taken = enforce_action(process->pid, process->name);
}

long get_max_memory_kb() {
    return max_memory_kb;
}

int get_max_fd_count() {
    return max_fd_count;
}
