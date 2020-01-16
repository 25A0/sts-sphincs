#include <stdio.h>

int run_bench(int (*test_fun)(void), char* description)
{
  printf("%s\n", description);
  int err = (*test_fun)();
  if(err) {
    printf("Fail in: %s: %d\n", description, err);
  }
  return err;
}

void print_cycles(const char* desc, unsigned long start, unsigned long end)
{
  printf("%24s: %24lu cycles\n", desc, end - start);
}

void print_bytes(const char* desc, unsigned long bytes)
{
  printf("%24s: %24lu B\n", desc, bytes);
}
