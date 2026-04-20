#include <stdio.h>
#include <signal.h>
#include "monitor.h"
#include "detection.h"
#include "sandbox.h"

#define MONITOR_INTERVAL_SECONDS 2U

int main(int argc, char *argv[]) {
    // If the user provided extra arguments (e.g., "./processguard ls -l")
    if (argc > 1) {
        printf("Initializing ProcessGuard Sandbox Mode...\n\n");
        // Pass everything after "./processguard" to the sandbox
        run_in_sandbox(&argv[1]);
        return 0;
    }

    // Otherwise, run the standard Monitor/IDS mode
    printf("Initializing ProcessGuard Monitor Mode...\n");
    load_rules();
    signal(SIGINT, handle_monitor_signal);
    signal(SIGTERM, handle_monitor_signal);
    printf("Starting continuous monitoring every %u seconds.\n", MONITOR_INTERVAL_SECONDS);
    printf("Press Ctrl+C to stop monitoring gracefully.\n\n");

    run_monitor_loop(MONITOR_INTERVAL_SECONDS);
    
    return 0;
}
