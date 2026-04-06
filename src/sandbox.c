#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include "sandbox.h"

void run_in_sandbox(char **argv) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("[\033[0;31mERROR\033[0m] Fork failed");
        return;
    }

    if (pid == 0) { 
        // --- WE ARE IN THE CHILD PROCESS ---
        
        // 1. Set the memory limit (RLIMIT_AS = Address Space)
        struct rlimit mem_limit;
        long limit_bytes = 20 * 1024 * 1024; // 20 MB
        mem_limit.rlim_cur = limit_bytes; // Soft limit
        mem_limit.rlim_max = limit_bytes; // Hard limit
        
        if (setrlimit(RLIMIT_AS, &mem_limit) != 0) {
            perror("Failed to set resource limit");
            exit(1);
        }

        printf("[\033[0;32mSANDBOX\033[0m] Securing environment. Max Memory: 20MB\n");
        printf("[\033[0;32mSANDBOX\033[0m] Executing command: %s\n", argv[0]);
        
        // 2. Execute the untrusted program
        execvp(argv[0], argv);
        
        // If execvp fails (e.g., command not found), it reaches this line
        perror("[\033[0;31mERROR\033[0m] Execution failed");
        exit(1);
        
    } else {
        // --- WE ARE IN THE PARENT PROCESS (ProcessGuard) ---
        int status;
        waitpid(pid, &status, 0); // Wait for the sandboxed program to finish
        printf("[\033[0;34mSANDBOX\033[0m] Sandboxed process terminated.\n");
    }
}