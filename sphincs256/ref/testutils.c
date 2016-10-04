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

int run_test(int (*test_fun)(void), char* description)
{
  int err = (*test_fun)();
  if(err) {
    printf("Fail in: %s\n", description);
  }
  return err;
}

void hexdump(unsigned char *data, int start, int len)
{
  int i;
  for(i = 0; i < len; i++) {
    if(i % 32 == 0) printf("\n%04d: ", i);
    printf("%02x", data[start + i]);
    if(i % 2) printf(" ");
  }
  printf("\n");
}
