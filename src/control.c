#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include "control.h"
#include "logger.h"

int enforce_action(int pid, const char *name) {
    // SAFEGUARD: Never touch core system processes
    if (pid <= 100) {
        printf("[\033[0;33mSAFEGUARD\033[0m] PID %d (%s) is a system process. Action blocked.\n", pid, name);
        return 0;
    }

    // Send SIGSTOP to safely pause the process
    if (kill(pid, SIGSTOP) == 0) {
        char action_msg[256];
        snprintf(action_msg, sizeof(action_msg), "ACTION TAKEN: Paused rogue process %s (PID: %d)", name, pid);

        // Print action to terminal in BLUE text
        printf("\033[0;34m%s\033[0m\n", action_msg);

        // Log the action
        log_event(action_msg);
        return 1;
    } else {
        printf("[\033[0;31mERROR\033[0m] Failed to pause PID %d. Run with sudo?\n", pid);
        return 0;
    }
}

static int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char) *str)) return 0;
        str++;
    }
    return 1;
}

static int read_ppid_from_stat(int pid) {
    char path[256];
    char stat_content[1024];
    FILE *fp_stat;
    int ppid = 0;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp_stat = fopen(path, "r");
    if (!fp_stat) {
        return 0;
    }

    if (fgets(stat_content, sizeof(stat_content), fp_stat)) {
        char *token;
        int field = 0;

        token = strtok(stat_content, " ");
        while (token != NULL && field < 3) {
            field++;
            token = strtok(NULL, " ");
        }

        if (token != NULL) {
            ppid = atoi(token);
        }
    }

    fclose(fp_stat);
    return ppid;
}

void enforce_mass_action(int ppid) {
    DIR *dir;
    struct dirent *entry;
    int stopped_count = 0;

    // SAFEGUARD: Never touch core system processes
    if (ppid <= 100) {
        printf("[\033[0;33mSAFEGUARD\033[0m] Parent PID %d is a system process. Mass action blocked.\n", ppid);
        return;
    }

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return;
    }

    printf("\033[0;34m[MASS ACTION] Stopping parent PID %d and all its children...\033[0m\n", ppid);

    while ((entry = readdir(dir)) != NULL) {
        int pid;

        if (!is_numeric(entry->d_name)) {
            continue;
        }

        pid = atoi(entry->d_name);

        // SAFEGUARD: Skip core system processes
        if (pid <= 100) {
            continue;
        }

        // Check if this process has the target PPID
        int current_ppid = read_ppid_from_stat(pid);
        if (current_ppid == ppid || pid == ppid) {
            if (kill(pid, SIGSTOP) == 0) {
                stopped_count++;
            }
        }
    }

    closedir(dir);

    char action_msg[256];
    snprintf(action_msg, sizeof(action_msg), "MASS ACTION: Stopped %d processes (parent PID %d and children)", stopped_count, ppid);
    printf("\033[0;34m%s\033[0m\n", action_msg);
    log_event(action_msg);
}
