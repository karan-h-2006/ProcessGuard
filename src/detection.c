#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "detection.h"
#include "logger.h"
#include "control.h"

long max_memory_kb = 500000; // Default fallback
int max_fd_count = 100;      // Default fallback

void load_rules() {
    FILE *fp = fopen("conf/rules.conf", "r");
    if (fp) {
        char line[256];
        // Read the file line by line to support multiple rules safely
        while (fgets(line, sizeof(line), fp)) {
            sscanf(line, "MAX_MEMORY_KB=%ld", &max_memory_kb);
            sscanf(line, "MAX_FD_COUNT=%d", &max_fd_count);
        }
        fclose(fp);
        printf("[\033[0;32mOK\033[0m] Rules loaded: Mem Limit=%ld kB, FD Limit=%d\n", max_memory_kb, max_fd_count);
    } else {
        printf("[\033[0;33mWARN\033[0m] Could not open conf/rules.conf. Using defaults.\n");
    }
}

void analyze_process(ProcessInfo *process) {
    char alert_msg[512] = "";
    int violation_found = 0;

    // Rule 1: High Memory Usage
    if (process->memory_kb > max_memory_kb) {
        snprintf(alert_msg, sizeof(alert_msg), "Process %d (%s) exceeded memory limit: %ld kB", 
                 process->pid, process->name, process->memory_kb);
        violation_found = 1;
    }

    // Rule 2: File Descriptor Spam
    if (process->fd_count > max_fd_count) {
        snprintf(alert_msg, sizeof(alert_msg), "Process %d (%s) FD Spam detected: %d open files", 
                 process->pid, process->name, process->fd_count);
        violation_found = 1;
    }

    // If any rule was broken, execute the response
    if (violation_found) {
        printf("\033[0;31m>>> THREAT DETECTED: %s <<<\033[0m\n", alert_msg);
        log_event(alert_msg);
        enforce_action(process->pid, process->name);
    }
}