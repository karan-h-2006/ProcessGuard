#include <stdio.h>
#include "monitor.h"

int main() {
    printf("Initializing ProcessGuard Monitor...\n");
    printf("Fetching live kernel data...\n\n");
    
    // Call your function!
    scan_processes();
    
    return 0;
}