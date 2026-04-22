#ifndef LOGGER_H
#define LOGGER_H

void log_event(const char *message);
void log_sandbox_event(const char *stage, const char *status, const char *target, const char *detail);

#endif
