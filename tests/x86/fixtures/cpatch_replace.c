#include <stdio.h>

int target_func(void) {
  puts("patched-target-func");
  fflush(stdout);
  return 0;
}
