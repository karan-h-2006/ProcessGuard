#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
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

/* Safe CPU pressure simulator that spins for a short, bounded interval. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    int busy_percent = 30;
    volatile unsigned long long counter = 0;
    struct timespec loop_start;
    struct timespec now;

    if (argc > 1 && equals_ignore_case(argv[1], "safe")) {
        hold_seconds = 8;
        busy_percent = 30;
    } else if (argc > 1 && equals_ignore_case(argv[1], "unsafe")) {
        hold_seconds = 10;
        busy_percent = 100;
    } else if (argc > 1) {
        hold_seconds = (int) strtol(argv[1], NULL, 10);
    }
    if (argc > 2) {
        busy_percent = (int) strtol(argv[2], NULL, 10);
    }

    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }
    if (busy_percent < 5) {
        busy_percent = 5;
    }
    if (busy_percent > 100) {
        busy_percent = 100;
    }

    alarm((unsigned) hold_seconds + 2U);
    clock_gettime(CLOCK_MONOTONIC, &loop_start);

    printf("[SIM_CPU] Mode: %s\n", busy_percent <= 40 ? "safe-profile" : "unsafe-profile");
    printf("[SIM_CPU] Target busy time: %d%% for %d seconds.\n", busy_percent, hold_seconds);

    while (1) {
        long elapsed_ms;
        long busy_us = busy_percent * 10000L;
        long idle_us = 1000000L - busy_us;
        struct timespec busy_start;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ms = (long) ((now.tv_sec - loop_start.tv_sec) * 1000L +
                             (now.tv_nsec - loop_start.tv_nsec) / 1000000L);
        if (elapsed_ms >= hold_seconds * 1000L) {
            break;
        }

        clock_gettime(CLOCK_MONOTONIC, &busy_start);
        while (1) {
            long busy_elapsed_us;

            counter += 3;
            counter ^= (counter << 1);
            counter += 7;

            clock_gettime(CLOCK_MONOTONIC, &now);
            busy_elapsed_us = (long) ((now.tv_sec - busy_start.tv_sec) * 1000000L +
                                      (now.tv_nsec - busy_start.tv_nsec) / 1000L);
            if (busy_elapsed_us >= busy_us) {
                break;
            }
        }

        if (idle_us > 0) {
            usleep((useconds_t) idle_us);
        }
    }

    printf("[SIM_CPU] Completed safely. Counter=%llu\n", counter);
    return 0;
}
