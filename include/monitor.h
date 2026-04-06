#ifndef MONITOR_H
#define MONITOR_H

// This struct holds the data for a single process
typedef struct {
    int pid;
    char name[256];
    long memory_kb;
} ProcessInfo;

// Function prototype so main.c knows this function exists
void scan_processes();

#endif