__attribute__((noinline)) long target_func(long a, long b) {
  if (a == 7 && b == 5) {
    return 2;
  }
  return 99;
}
