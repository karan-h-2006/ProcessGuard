#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

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

/* Safe memory pressure simulator with explicit caps and automatic shutdown. */
int main(int argc, char *argv[]) {
    int hold_seconds = 5;
    long megabytes = 48;
    size_t chunk_size = 1024 * 1024;
    char **chunks = NULL;
    long i;

    if (argc > 1 && equals_ignore_case(argv[1], "safe")) {
        megabytes = 48;
        hold_seconds = 5;
    } else if (argc > 1 && equals_ignore_case(argv[1], "unsafe")) {
        megabytes = 160;
        hold_seconds = 8;
    } else if (argc > 1) {
        megabytes = strtol(argv[1], NULL, 10);
    }
    if (argc > 2 && !equals_ignore_case(argv[1], "safe") && !equals_ignore_case(argv[1], "unsafe")) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    } else if (argc > 2 && (equals_ignore_case(argv[1], "safe") || equals_ignore_case(argv[1], "unsafe"))) {
        hold_seconds = (int) strtol(argv[2], NULL, 10);
    }

    if (megabytes < 1) {
        megabytes = 1;
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

    printf("[SIM_MEM] Mode: %s\n",
           megabytes <= 64 ? "safe-profile" : "unsafe-profile");
    printf("[SIM_MEM] Target total memory: %ld MB\n", megabytes);
    printf("[SIM_MEM] Allocation unit: 1 MB per chunk (repeated until target total is reached)\n");
    printf("[SIM_MEM] Hold time after allocation: %d seconds\n", hold_seconds);

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
