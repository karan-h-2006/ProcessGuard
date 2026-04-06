#include <stdio.h>
#include <signal.h>
#include "control.h"
#include "logger.h"

void enforce_action(int pid, const char *name) {
    // SAFEGUARD: Never touch core system processes
    if (pid <= 100) {
        printf("[\033[0;33mSAFEGUARD\033[0m] PID %d (%s) is a system process. Action blocked.\n", pid, name);
        return;
    }

    // Send SIGSTOP to safely pause the process
    if (kill(pid, SIGSTOP) == 0) {
        char action_msg[256];
        snprintf(action_msg, sizeof(action_msg), "ACTION TAKEN: Paused rogue process %s (PID: %d)", name, pid);
        
        // Print action to terminal in BLUE text
        printf("\033[0;34m%s\033[0m\n", action_msg);
        
        // Log the action
        log_event(action_msg);
    } else {
        printf("[\033[0;31mERROR\033[0m] Failed to pause PID %d. Run with sudo?\n", pid);
    }
}