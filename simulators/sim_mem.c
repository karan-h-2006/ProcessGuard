#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
    // 🛡️ THE DEAD MAN'S SWITCH: The OS will kill this program in exactly 10 seconds.
    alarm(10); 

    printf("[\033[0;35mSIMULATOR\033[0m] Starting Memory Hog...\n");
    printf("[\033[0;35mSIMULATOR\033[0m] Attempting to hoard 600MB of RAM.\n");
    
    long size = 600 * 1024 * 1024; // 600 MB
    char *buffer = (char *)malloc(size);
    
    if (buffer) {
        // In Linux, memory isn't actually "used" until you write to it.
        // We fill it with 'A's to force the OS to register the RAM usage.
        memset(buffer, 'A', size);
        printf("[\033[0;35mSIMULATOR\033[0m] RAM successfully hoarded. Waiting for ProcessGuard to catch me...\n");
        sleep(10); 
    } else {
        printf("[\033[0;31mERROR\033[0m] System refused to allocate memory.\n");
    }
    
    return 0;
}