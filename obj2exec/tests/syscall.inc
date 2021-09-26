#include "syscall.h"

/* Print sz bytes starting at msg to the terminal */
int sys_print(const char* msg, long int sz)
{
  long int res;

  asm("movq $1, %%rax; movq $1, %%rdi; movq %1, %%rsi; movq %2, %%rdx; syscall"
      : "=a" (res)                                   // output
      : "g"(msg), "g"(sz)                            // input
      : "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9" // clobbers
     );
  
  return res;
}

/* Exit with return code ret */
void sys_exit(int ret)
{
  asm("mov $60, %%rax; mov %0, %%rdi; syscall"
      : 
      : "g" ((long int) ret)
      : "%rax", "%rdi");
}

