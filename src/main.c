#include <stdio.h>
#include "monitor.h"
#include "detection.h"

int main() {
    printf("Initializing ProcessGuard...\n");
    load_rules(); // Call Vikas's initialization
    printf("Fetching live kernel data...\n\n");
    
    scan_processes(); // Call Karan's monitor
    
    return 0;
}