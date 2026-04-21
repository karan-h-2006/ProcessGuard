#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// Simple controlled fork bomb test
// Spawns multiple child processes to test PPID tracking
int main() {
    // 🛡️ THE DEAD MAN'S SWITCH: Kills the parent in 15 seconds safely.
    alarm(15);

    printf("[TEST] Starting controlled fork bomb test...\n");
    printf("[TEST] This process will spawn 35 children to trigger the fork bomb detection\n");
    printf("[TEST] Parent PID: %d\n", getpid());
    
    int children_spawned = 0;
    int target_children = 35; // Exceeds MAX_CHILDREN_PER_PPID=30
    
    for (int i = 0; i < target_children; i++) {
        pid_t pid = fork();
        
        if (pid == 0) {
            // --- CHILD PROCESS ---
            // 🛡️ Child Dead Man's Switch: Ensures children don't become lingering orphans
            alarm(15); 
            
            printf("[CHILD %d] Child PID: %d, Parent PID: %d\n", i, getpid(), getppid());
            sleep(15); // Keep children alive just long enough for detection
            exit(0);
        } else if (pid < 0) {
            // --- ERROR ---
            perror("fork failed");
            break;
        } else {
            // --- PARENT PROCESS ---
            children_spawned++;
            printf("[PARENT] Spawned child #%d (PID: %d)\n", children_spawned, pid);
            usleep(100000); // 0.1 second delay between forks
        }
    }
    
    printf("[TEST] Spawned %d children. Waiting for ProcessGuard detection...\n", children_spawned);
    
    // Wait for all children to exit or be killed
    for (int i = 0; i < children_spawned; i++) {
        wait(NULL);
    }
    
    printf("[TEST] Test complete\n");
    return 0;
}