#ifndef DETECTION_H
#define DETECTION_H
#include "monitor.h" // We need Karan's ProcessInfo struct!

// Functions to load rules and check processes
void load_rules();
void begin_detection_cycle();
void end_detection_cycle();
void analyze_process(ProcessInfo *process);
long get_max_memory_kb();
int get_max_fd_count();

#endif
