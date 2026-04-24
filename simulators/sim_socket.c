#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Safe socket flood simulator using local socketpairs only. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    int target_pairs = 20;
    int (*pairs)[2];
    int i;

    if (argc > 1) {
        target_pairs = (int) strtol(argv[1], NULL, 10);
    }
    if (argc > 2) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (target_pairs < 4) {
        target_pairs = 4;
    }
    if (target_pairs > 32) {
        target_pairs = 32;
    }
    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 2U);
    pairs = calloc((size_t) target_pairs, sizeof(*pairs));
    if (!pairs) {
        perror("calloc failed");
        return 1;
    }

    printf("[SIM_SOCKET] Opening %d socket pairs for %d seconds.\n", target_pairs, hold_seconds);

    for (i = 0; i < target_pairs; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) != 0) {
            perror("socketpair failed");
            break;
        }
        usleep(10000);
    }

    sleep((unsigned) hold_seconds);

    for (i = 0; i < target_pairs; i++) {
        if (pairs[i][0] > 0) {
            close(pairs[i][0]);
        }
        if (pairs[i][1] > 0) {
            close(pairs[i][1]);
        }
    }

    free(pairs);
    printf("[SIM_SOCKET] Completed safely.\n");
    return 0;
}
