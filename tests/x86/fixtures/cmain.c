#include <stdio.h>
#include <unistd.h>

int target_func(void) {
  puts("orig-target-func");
  fflush(stdout);
  return 0;
}

int main(void) {
  while (1) {
    target_func();
    usleep(1000000);
  }
  return 0;
}
