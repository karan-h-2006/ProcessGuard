#include <stdio.h>
#include <time.h>
#include <string.h>
#include "logger.h"

/* Append one timestamped security event to the project log file. */
void log_event(const char *message) {
    FILE *fp = fopen("processguard.log", "a");

    if (!fp) {
        return;
    }

    {
        time_t now = time(NULL);
        char *time_str = ctime(&now);

        if (time_str != NULL) {
            time_str[strcspn(time_str, "\n")] = '\0';
            fprintf(fp, "[%s] %s\n", time_str, message);
        }
    }

    fclose(fp);
}
