#ifndef CONTROL_H
#define CONTROL_H

#include "monitor.h"

typedef enum {
    USER_ACTION_NONE = 0,
    USER_ACTION_ALLOW = 1,
    USER_ACTION_PAUSE = 2,
    USER_ACTION_TERMINATE = 3,
    USER_ACTION_KILL = 4
} UserAction;

void enforce_action(ProcessInfo *process);
void enforce_mass_action(int ppid);
void process_control_queue(void);
int user_action_is_allowed(int pid);

#endif
