#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include "monitor.h"
#include "detection.h"

// Helper function to check if a folder name is a number (a PID)
int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit(*str)) return 0;
        str++;
    }
    return 1;
}

void scan_processes() {
    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return;
    }

    struct dirent *entry;
    
    // Print a nice table header
    printf("%-10s %-25s %-15s\n", "PID", "NAME", "MEMORY (kB)");
    printf("--------------------------------------------------\n");

    // Loop through everything inside /proc
    while ((entry = readdir(dir)) != NULL) {
        // If it is a directory and its name is a number, it's a process!
        if (entry->d_type == DT_DIR && is_numeric(entry->d_name)) {
            int pid = atoi(entry->d_name);
            char path[256];
            char name[256] = "Unknown";
            long mem_kb = 0;

            // 1. Read the Process Name from /proc/[PID]/comm
            snprintf(path, sizeof(path), "/proc/%d/comm", pid);
            FILE *fp_comm = fopen(path, "r");
            if (fp_comm) {
                if (fgets(name, sizeof(name), fp_comm)) {
                    name[strcspn(name, "\n")] = 0; // Remove the hidden newline character
                }
                fclose(fp_comm);
            }

            // 2. Read the Memory Usage from /proc/[PID]/status
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            FILE *fp_status = fopen(path, "r");
            if (fp_status) {
                char line[256];
                // Read the file line by line until we find "VmRSS:"
                while (fgets(line, sizeof(line), fp_status)) {
                    if (strncmp(line, "VmRSS:", 6) == 0) {
                        sscanf(line, "VmRSS: %ld kB", &mem_kb);
                        break;
                    }
                }
                fclose(fp_status);
            }

            // Print the process info (filtering out empty kernel threads for cleaner output)
            
                // Print the process info
            if (mem_kb > 0) {
                printf("%-10d %-25s %ld kB\n", pid, name, mem_kb);
                
                // --- NEW INTEGRATION CODE ---
                // Package the data into the struct and send it to Vikas's Engine
                ProcessInfo info;
                info.pid = pid;
                strncpy(info.name, name, sizeof(info.name));
                info.memory_kb = mem_kb;
                
                analyze_process(&info);
            }
            
        }
    }
    closedir(dir);
}