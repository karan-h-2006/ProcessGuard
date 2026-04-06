#include <stdio.h>
#include <stdlib.h>
#include "detection.h"
#include "logger.h"

long max_memory_kb = 500000; // Default fallback value

void load_rules() {
    FILE *fp = fopen("conf/rules.conf", "r");
    if (fp) {
        fscanf(fp, "MAX_MEMORY_KB=%ld", &max_memory_kb);
        fclose(fp);
        printf("[\033[0;32mOK\033[0m] Rules loaded: Threshold set to %ld kB\n", max_memory_kb);
    } else {
        printf("[\033[0;33mWARN\033[0m] Could not open conf/rules.conf. Using defaults.\n");
    }
}

void analyze_process(ProcessInfo *process) {
    // Rule 1: High Memory Usage Detection
    if (process->memory_kb > max_memory_kb) {
        char alert_msg[512];
        snprintf(alert_msg, sizeof(alert_msg), "Process %d (%s) exceeded memory limit: %ld kB", 
                 process->pid, process->name, process->memory_kb);
        
        // Print to terminal in RED text
        printf("\033[0;31m>>> THREAT DETECTED: %s <<<\033[0m\n", alert_msg);
        
        // Log to file
        log_event(alert_msg);
    }
}