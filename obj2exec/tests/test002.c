#include "test.h"

int fibonacci(int n)
{
  if (n == 0 || n == 1) return 1;
  return fibonacci(n-2) + fibonacci(n-1);
}

void _start() 
{
  int ret;
  ret = fibonacci(10);
  sys_exit(ret);
}

