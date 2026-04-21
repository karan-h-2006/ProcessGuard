#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* Safe file-descriptor burst simulator with strict upper bounds. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    int target_fds = 48;
    int *fds;
    int i;

    if (argc > 1) {
        target_fds = (int) strtol(argv[1], NULL, 10);
    }
    if (argc > 2) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (target_fds < 8) {
        target_fds = 8;
    }
    if (target_fds > 96) {
        target_fds = 96;
    }
    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 2U);
    fds = (int *) calloc((size_t) target_fds, sizeof(int));
    if (!fds) {
        perror("calloc failed");
        return 1;
    }

    for (i = 0; i < target_fds; i++) {
        fds[i] = -1;
    }

    printf("[SIM_FD] Opening up to %d handles for %d seconds.\n", target_fds, hold_seconds);

    for (i = 0; i < target_fds; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] < 0) {
            perror("open failed");
            break;
        }
        usleep(15000);
    }

    printf("[SIM_FD] Waiting for ProcessGuard observation.\n");
    sleep((unsigned) hold_seconds);

    for (i = 0; i < target_fds; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    free(fds);

    printf("[SIM_FD] Completed safely.\n");
    return 0;
}
