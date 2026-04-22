#ifndef DETECTION_H
#define DETECTION_H

#include "monitor.h"

typedef enum {
    ACTION_MODE_PAUSE = 0,
    ACTION_MODE_TERMINATE = 1,
    ACTION_MODE_KILL = 2,
    ACTION_MODE_OBSERVE = 3
} ActionMode;

/* Tunable rules loaded from conf/rules.conf. */
typedef struct {
    long max_memory_kb;
    int max_fd_count;
    int max_socket_count;
    int max_threads;
    double max_cpu_percent;
    long max_memory_growth_kb;
    int max_fd_growth;
    int max_children_per_ppid;
    int min_alert_score;
    int alert_persistence_cycles;
    int monitor_interval_seconds;
    long sandbox_memory_kb;
    int sandbox_fd_limit;
    int sandbox_cpu_seconds;
    int sandbox_eval_seconds;
    int sandbox_promote_after_clean;
    int terminate_grace_ms;
    int allow_cross_uid_action;
    ActionMode action_mode;
} DetectionRules;

void load_rules(void);
const DetectionRules *get_rules(void);
void begin_detection_cycle(void);
void end_detection_cycle(void);
void analyze_process(ProcessInfo *process);

#endif
