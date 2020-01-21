#include <stdio.h>

int compare(unsigned char *x, unsigned char *y, unsigned long long l)
{
  int i;
  for (i = 0; i < l; ++i)
  {
    if(x[i] != y[i]) {
      return 1;
    }
  }
  return 0;
}

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
  int cycle_width = 40;
  unsigned char bar[cycle_width];
  unsigned char clear[cycle_width];
  int i = 0;
  for(; i < cycle_width; i++) {
    bar[i] = ((i+1) % 5) ? '-' : '+';
    clear[i] = ' ';
  }
  bar[cycle_width - 1] = 0;
  clear[cycle_width - 1] = 0;

  int log_2 = 0;
  unsigned long cycles = end - start;
  while(cycles >>= 1) {
    log_2++;
  }

  cycles = end - start;
  double frac = (double) cycles / (double)((unsigned long)1 << log_2);

  printf("%24s: %.*s%.*s %4.2f * 2^%2d cycles\n",
         desc,
         log_2, bar,
         cycle_width - log_2, clear,
         frac, log_2);
}

void print_bytes(const char* desc, unsigned long bytes)
{
  printf("%24s: %24lu B\n", desc, bytes);
}

void print_number(const char* desc, unsigned long n)
{
  printf("%24s: %24lu\n", desc, n);
}
