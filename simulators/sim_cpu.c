#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* Safe CPU pressure simulator that spins for a short, bounded interval. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    volatile unsigned long long counter = 0;
    time_t start_time;

    if (argc > 1) {
        hold_seconds = (int) strtol(argv[1], NULL, 10);
    }

    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 2U);
    start_time = time(NULL);

    printf("[SIM_CPU] Spinning for %d seconds.\n", hold_seconds);

    while ((int) difftime(time(NULL), start_time) < hold_seconds) {
        counter += 3;
        counter ^= (counter << 1);
        counter += 7;
    }

    printf("[SIM_CPU] Completed safely. Counter=%llu\n", counter);
    return 0;
}
