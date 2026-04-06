#include <stdio.h>
#include "monitor.h"
#include "detection.h"
#include "sandbox.h"

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
    printf("Fetching live kernel data...\n\n");
    
    scan_processes(); 
    
    return 0;
}