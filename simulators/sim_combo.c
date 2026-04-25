#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

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

/* Combined simulator that triggers memory and FD rules together. */
int main(int argc, char *argv[]) {
    int hold_seconds = 5;
    long megabytes = 64;
    int target_fds = 20;
    char **chunks;
    int *fds;
    int i;

    if (argc > 1 && equals_ignore_case(argv[1], "safe")) {
        megabytes = 64;
        target_fds = 20;
        hold_seconds = 5;
    } else if (argc > 1 && equals_ignore_case(argv[1], "unsafe")) {
        megabytes = 112;
        target_fds = 48;
        hold_seconds = 8;
    } else if (argc > 1) {
        megabytes = strtol(argv[1], NULL, 10);
    }
    if (argc > 2 && !equals_ignore_case(argv[1], "safe") && !equals_ignore_case(argv[1], "unsafe")) {
        target_fds = (int) strtol(argv[2], NULL, 10);
    }
    if (argc > 3 && !equals_ignore_case(argv[1], "safe") && !equals_ignore_case(argv[1], "unsafe")) {
        hold_seconds = (int) strtol(argv[3], NULL, 10);
    } else if (argc > 2 && (equals_ignore_case(argv[1], "safe") || equals_ignore_case(argv[1], "unsafe"))) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (megabytes < 32) {
        megabytes = 32;
    }
    if (megabytes > 160) {
        megabytes = 160;
    }
    if (target_fds < 8) {
        target_fds = 8;
    }
    if (target_fds > 64) {
        target_fds = 64;
    }
    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 2U);
    chunks = calloc((size_t) megabytes, sizeof(char *));
    fds = calloc((size_t) target_fds, sizeof(int));
    if (!chunks || !fds) {
        perror("calloc failed");
        free(chunks);
        free(fds);
        return 1;
    }

    for (i = 0; i < target_fds; i++) {
        fds[i] = -1;
    }

    printf("[SIM_COMBO] Mode: %s\n",
           (megabytes <= 64 && target_fds <= 24) ? "safe-profile" : "unsafe-profile");
    printf("[SIM_COMBO] Allocating %ld MB and opening %d FDs for %d seconds.\n",
           megabytes, target_fds, hold_seconds);

    for (i = 0; i < megabytes; i++) {
        chunks[i] = malloc(1024 * 1024);
        if (!chunks[i]) {
            break;
        }
        memset(chunks[i], 0x5A, 1024 * 1024);
    }

    for (i = 0; i < target_fds; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] < 0) {
            break;
        }
    }

    sleep((unsigned) hold_seconds);

    for (i = 0; i < target_fds; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    for (i = 0; i < megabytes; i++) {
        free(chunks[i]);
    }

    free(fds);
    free(chunks);
    printf("[SIM_COMBO] Completed safely.\n");
    return 0;
}
