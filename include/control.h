#ifndef CONTROL_H
#define CONTROL_H

// Function to take action against a malicious process
int enforce_action(int pid, const char *name);

// Function to stop parent and all its children (fork bomb response)
void enforce_mass_action(int ppid);

#endif
