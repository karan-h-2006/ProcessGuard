#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // 🛡️ THE DEAD MAN'S SWITCH: The OS will kill this program in exactly 10 seconds.
    alarm(10); 

    printf("[\033[0;35mSIMULATOR\033[0m] Starting File Descriptor Spam...\n");
    printf("[\033[0;35mSIMULATOR\033[0m] Opening 60 files rapidly.\n");
    
    // Open 60 dummy files
    for (int i = 0; i < 60; i++) {
        open("/dev/null", O_RDONLY);
    }
    
    printf("[\033[0;35mSIMULATOR\033[0m] Malicious payload delivered. Waiting for ProcessGuard to catch me...\n");
    
    // Sleep to give ProcessGuard time to detect it
    sleep(10);
    
    return 0;
}