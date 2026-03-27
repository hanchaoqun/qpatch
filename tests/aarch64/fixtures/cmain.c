#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) long target_func(long a, long b) {
  long c = a + b;
  if (c == 12) {
    return 1;
  }
  return 1;
}

__attribute__((noinline)) int tiny_func(void) {
  return 1;
}

int main(void) {
  while (1) {
    long ret = target_func(7, 5);
    tiny_func();
    if (ret == 1) {
      puts("orig-target-func");
    } else if (ret == 2) {
      puts("patched-target-func");
    } else {
      puts("bad-abi-target-func");
    }
    fflush(stdout);
    usleep(1000000);
  }
  return 0;
}
