#include <stdio.h>

void print_cycles(const char* desc, unsigned long start, unsigned long end)
{
  printf("%24s: %24lu cycles\n", desc, end - start);
}

void print_bytes(const char* desc, unsigned long bytes)
{
  printf("%24s: %24lu B\n", desc, bytes);
}
