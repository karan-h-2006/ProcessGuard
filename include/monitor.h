#ifndef MONITOR_H
#define MONITOR_H

// This struct holds the data for a single process
typedef struct {
    int pid;
    char name[256];
    long memory_kb;
    int fd_count; // <-- NEW: Tracks open files
} ProcessInfo;

void scan_processes();

#endif