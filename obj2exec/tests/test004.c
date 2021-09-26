#include "test.h"

// Expected: message in .rodata
const char message[] = "Hello World!\n";

// Expected: buffer in .bss
char buffer[100];

// Expected: some_global_variable in .data
int global = 250;

// Copy string from src to dst and fill remaining bytes with zero
char* string_copy(char* dst, const char* src, int max) {
    int terminated = 0;
    for (int i = 0; i < max; i++) {
        if (!terminated) {
            terminated = (*src == 0);
            dst[i] = *(src++);
        }
        else {
            dst[i] = 0;
        }
    }
    return dst;
}

void _start() {
    global = 50;
    
    prints(message); // "Hello World\n"
    string_copy(buffer, message, sizeof(buffer)-1);
    prints(buffer); // "Hello World\n"
    buffer[0] = 'N';
    buffer[6] = 'B';
    prints(buffer); // "Nello Borld\n"

    sys_exit(71);
}