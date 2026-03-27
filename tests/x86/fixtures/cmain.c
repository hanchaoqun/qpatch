#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) int target_func(void) {
  volatile int x = 1;
  x = x + 2;
  x = x * 3;
  if (x == 9) {
    return 1;
  }
  return 1;
}

int main(void) {
  while (1) {
    int ret = target_func();
    if (ret == 1) {
      puts("orig-target-func");
    } else if (ret == 2) {
      puts("patched-target-func");
    } else {
      puts("unknown-target-func");
    }
    fflush(stdout);
    usleep(1000000);
  }
  return 0;
}
