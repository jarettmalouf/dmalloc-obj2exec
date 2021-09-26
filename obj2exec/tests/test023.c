#include "test.h"

// checkstr: we test that this is being printed so we know program has loaded
const char checkstr[] = "carrot\n";

// Check that global data cannot be executed

// If executed, the proccess with exit with an exit code of 99
char code_as_data[] = {
	0x48, 0xc7, 0xc0, 0x3c, 0x0, 0x0, 0x0, // mov rax,0x3c
	0x48, 0xc7, 0xc7, 0x63, 0x0, 0x0, 0x0, // mov rdi,0x63
	0x0f, 0x05};         		       // syscall

void _start() 
{
  sys_print(checkstr, sizeof(checkstr));

  void (*bad)(void) = (void (*)(void))(code_as_data);
  
  // Expect SEGFAULT
  bad();
  
  sys_exit(1);
}

