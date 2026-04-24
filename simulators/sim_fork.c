#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/* Controlled process-family growth simulator with hard limits and cleanup. */
int main(int argc, char *argv[]) {
    int children_spawned = 0;
    int target_children = 12;
    int hold_seconds = 8;
    int i;

    if (argc > 1) {
        target_children = (int) strtol(argv[1], NULL, 10);
    }
    if (argc > 2) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (target_children < 2) {
        target_children = 2;
    }
    if (target_children > 20) {
        target_children = 20;
    }
    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 3U);
    printf("[SIM_FORK] Parent PID %d spawning %d controlled children.\n", getpid(), target_children);

    for (i = 0; i < target_children; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            alarm((unsigned) hold_seconds + 2U);
            sleep((unsigned) hold_seconds);
            _exit(0);
        }

        if (pid < 0) {
            perror("fork failed");
            break;
        }

        children_spawned++;
        usleep(80000);
    }

    printf("[SIM_FORK] Spawned %d children. Waiting for cleanup.\n", children_spawned);

    for (i = 0; i < children_spawned; i++) {
        wait(NULL);
    }

    printf("[SIM_FORK] Completed safely.\n");
    return 0;
}
