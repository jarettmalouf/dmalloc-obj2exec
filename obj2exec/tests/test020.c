#include "test.h"

// checkstr: we test that this is being printed so we know program has loaded
const char checkstr[] = "apple\n";

// Check that .text segment cannot be modified

const char message[] = "Hello World\n";

void say_hello()
{
  sys_print(message, sizeof(message));
}

void _start() 
{
  sys_print(checkstr, sizeof(checkstr));

  say_hello();

  int* bad = (int*) say_hello;
  
  // Expect SEGFAULT
  *bad = 37;
  
  sys_exit(1);
}

