#include "test.h"

// checkstr: we test that this is being printed so we know program has loaded
const char checkstr[] = "pear\n";

// Check that a read only string cannot be written to

const char message[] = "This is a read only string\n";

void print_message()
{
  sys_print(message, sizeof(message));
}

void _start() 
{
  sys_print(checkstr, sizeof(checkstr));

  print_message();
  
  char* bad = message;
  
  // Expect SEGFAULT
  bad[0] = 'Q';
  
  sys_exit(1);
}

