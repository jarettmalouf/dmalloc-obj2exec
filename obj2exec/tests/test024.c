#include "test.h"

// checkstr: we test that this is being printed so we know program has loaded
const char checkstr[] = "orange\n";

// Check that bss data cannot be executed
const char code_as_data[] = {0, 0, 0, 0};

void _start() 
{
  sys_print(checkstr, sizeof(checkstr));

  void (*bad)(void) = (void (*)(void))(code_as_data);
  
  // Expect SEGFAULT
  bad();
  
  sys_exit(1);
}

