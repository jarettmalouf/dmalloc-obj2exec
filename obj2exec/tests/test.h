
/* Print sz bytes starting at msg to the terminal */
int sys_print(const char* msg, long int sz);

/* Print null-terminated string */
static inline int prints(const char* str)
{
  long int len = 0;
  while (str[len] != 0) len++;

  return sys_print(str, len);
}

/* Exit with return code ret */
void sys_exit(int ret);

/*
 * Include C source code directly for syscall.inc, which provides C routines
 * for Unix system calls.
 *
 * We only include the file in the source to avoid the need to link multiple
 * object files together, which is not the purpose of this assignment.
 *
 * DO NOT INCLUDE C FILES DIRECTLY IN REAL PROGRAMS!
 * See: https://stackoverflow.com/questions/10448047/include-c-file-in-another
 */
#include "syscall.inc"
