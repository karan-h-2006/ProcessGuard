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

void log_sandbox_event(const char *stage, const char *status, const char *target, const char *detail) {
    FILE *fp = fopen("sandbox_events.jsonl", "a");
    time_t now = time(NULL);
    struct tm tm_now;
    char timestamp[64];

    if (!fp) {
        return;
    }

    gmtime_r(&now, &tm_now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_now);

    fprintf(fp,
            "{\"timestamp\":\"%s\",\"stage\":\"%s\",\"status\":\"%s\",\"target\":\"%s\",\"detail\":\"%s\"}\n",
            timestamp,
            stage ? stage : "",
            status ? status : "",
            target ? target : "",
            detail ? detail : "");

    fclose(fp);
}
