#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// Simple controlled fork bomb test
// Spawns multiple child processes to test PPID tracking
int main() {
    printf("[TEST] Starting controlled fork bomb test...\n");
    printf("[TEST] This process will spawn 35 children to trigger the fork bomb detection\n");
    printf("[TEST] Parent PID: %d\n", getpid());
    
    int children_spawned = 0;
    int target_children = 35; // Exceeds MAX_CHILDREN_PER_PPID=30
    
    for (int i = 0; i < target_children; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process - just sleep and exit
            printf("[CHILD %d] Child PID: %d, Parent PID: %d\n", i, getpid(), getppid());
            sleep(30); // Keep children alive for detection
            exit(0);
        } else if (pid < 0) {
            perror("fork failed");
            break;
        } else {
            children_spawned++;
            printf("[PARENT] Spawned child #%d (PID: %d)\n", children_spawned, pid);
            usleep(100000); // Small delay between forks
        }
    }
    
    printf("[TEST] Spawned %d children. Waiting for ProcessGuard detection...\n", children_spawned);
    
    // Wait for all children
    for (int i = 0; i < children_spawned; i++) {
        wait(NULL);
    }
    
    printf("[TEST] Test complete\n");
    return 0;
}
