#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Safe memory pressure simulator with explicit caps and automatic shutdown. */
int main(int argc, char *argv[]) {
    int hold_seconds = 8;
    long megabytes = 128;
    size_t chunk_size = 1024 * 1024;
    char **chunks = NULL;
    long i;

    if (argc > 1) {
        megabytes = strtol(argv[1], NULL, 10);
    }
    if (argc > 2) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (megabytes < 8) {
        megabytes = 8;
    }
    if (megabytes > 192) {
        megabytes = 192;
    }
    if (hold_seconds < 2) {
        hold_seconds = 2;
    }
    if (hold_seconds > 12) {
        hold_seconds = 12;
    }

    alarm((unsigned) hold_seconds + 2U);
    chunks = (char **) calloc((size_t) megabytes, sizeof(char *));
    if (!chunks) {
        perror("calloc failed");
        return 1;
    }

    printf("[SIM_MEM] Allocating %ld MB in 1 MB chunks for %d seconds.\n", megabytes, hold_seconds);

    for (i = 0; i < megabytes; i++) {
        chunks[i] = (char *) malloc(chunk_size);
        if (!chunks[i]) {
            printf("[SIM_MEM] Allocation stopped early at %ld MB.\n", i);
            break;
        }
        memset(chunks[i], 0x41, chunk_size);
        usleep(30000);
    }

    printf("[SIM_MEM] Holding memory briefly for ProcessGuard observation.\n");
    sleep((unsigned) hold_seconds);

    for (i = 0; i < megabytes; i++) {
        free(chunks[i]);
    }
    free(chunks);

    printf("[SIM_MEM] Completed safely.\n");
    return 0;
}
