#include "test.h"

#define ARRSIZE 100

char should_be_zero[ARRSIZE] = {0};

void _start() 
{
  // Make sure bss segment initialized to 0
  for (int i = 0; i < ARRSIZE; i++) {
    if (should_be_zero[i]) {
      sys_exit(1);
    }
  }
  
  sys_exit(54);
}

