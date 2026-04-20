#ifndef MONITOR_H
#define MONITOR_H

#include <signal.h>

// This struct holds the data for a single process
typedef struct {
    int pid;
    char name[256];
    long memory_kb;
    int fd_count;
    int fd_access_denied;
    int alerted;
    int memory_alert;
    int fd_alert;
    int action_taken;
    char alert_reason[256];
} ProcessInfo;

void scan_processes();
void run_monitor_loop(unsigned interval_seconds);
void handle_monitor_signal(int signum);

#endif
