#ifndef MONITOR_H
#define MONITOR_H

#include <signal.h>

#define PROCESS_NAME_MAX 256
#define PROCESS_CMDLINE_MAX 512
#define PROCESS_REASON_MAX 512
#define PROCESS_ACTION_MAX 64
#define PROCESS_CATEGORY_MAX 64

/* Snapshot of one Linux process as observed during a monitoring cycle. */
typedef struct {
    int pid;
    int ppid;
    unsigned int uid;
    char name[PROCESS_NAME_MAX];
    char state[16];
    char cmdline[PROCESS_CMDLINE_MAX];
    long memory_kb;
    long memory_delta_kb;
    int fd_count;
    int fd_access_denied;
    int socket_count;
    int threads;
    int children_count;
    unsigned long long cpu_ticks;
    double cpu_percent;
    double runtime_seconds;
    int alerted;
    int memory_alert;
    int fd_alert;
    int socket_alert;
    int thread_alert;
    int cpu_alert;
    int growth_alert;
    int fork_alert;
    int alert_score;
    int sustained_alerts;
    int action_taken;
    int protected_process;
    int user_allowed;
    int manual_action_pending;
    int simulation_match;
    char action_label[PROCESS_ACTION_MAX];
    char category[PROCESS_CATEGORY_MAX];
    char alert_reason[PROCESS_REASON_MAX];
} ProcessInfo;

void scan_processes(void);
void run_monitor_loop(unsigned interval_seconds);
void handle_monitor_signal(int signum);

#endif
