#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

static int equals_ignore_case(const char *left, const char *right) {
    while (*left && *right) {
        char a = (char) tolower((unsigned char) *left);
        char b = (char) tolower((unsigned char) *right);

        if (a != b) {
            return 0;
        }

        left++;
        right++;
    }

    return *left == '\0' && *right == '\0';
}

/* Safe file-descriptor burst simulator with strict upper bounds. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    int target_fds = 20;
    int *fds;
    int i;

    if (argc > 1 && equals_ignore_case(argv[1], "safe")) {
        target_fds = 20;
        hold_seconds = 8;
    } else if (argc > 1 && equals_ignore_case(argv[1], "unsafe")) {
        target_fds = 72;
        hold_seconds = 10;
    } else if (argc > 1) {
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

    printf("[SIM_FD] Mode: %s\n",
           target_fds <= 24 ? "safe-profile" : "unsafe-profile");
    printf("[SIM_FD] Target open file descriptors: %d\n", target_fds);
    printf("[SIM_FD] Hold time after opening descriptors: %d seconds\n", hold_seconds);

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
