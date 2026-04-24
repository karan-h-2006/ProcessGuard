#include <stdio.h>
#include <signal.h>
#include "monitor.h"
#include "detection.h"
#include "sandbox.h"

int main(int argc, char *argv[]) {
    const DetectionRules *rules;

    load_rules();
    rules = get_rules();

    if (argc > 1) {
        printf("Initializing ProcessGuard Sandbox Review Mode...\n");
        printf("Sandbox evaluation window: %d seconds\n\n", rules->sandbox_eval_seconds);
        run_in_sandbox(&argv[1]);
        return 0;
    }

    printf("Initializing ProcessGuard Monitor Mode...\n");
    signal(SIGINT, handle_monitor_signal);
    signal(SIGTERM, handle_monitor_signal);
    printf("Starting continuous monitoring every %d seconds.\n", rules->monitor_interval_seconds);
    printf("Press Ctrl+C to stop monitoring gracefully.\n\n");

    run_monitor_loop((unsigned) rules->monitor_interval_seconds);
    return 0;
}
