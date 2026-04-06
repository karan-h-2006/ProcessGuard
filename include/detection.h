#ifndef DETECTION_H
#define DETECTION_H
#include "monitor.h" // We need Karan's ProcessInfo struct!

// Functions to load rules and check processes
void load_rules();
void analyze_process(ProcessInfo *process);

#endif