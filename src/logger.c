#include <stdio.h>
#include <time.h>
#include <string.h>
#include "logger.h"

void log_event(const char *message) {
    FILE *fp = fopen("processguard.log", "a"); // "a" means append
    if (fp) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0'; // Strip the hidden newline
        
        fprintf(fp, "[%s] SECURITY ALERT: %s\n", time_str, message);
        fclose(fp);
    }
}