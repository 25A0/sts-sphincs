#include <stdio.h>
#include "randombytes.h"
#include <stdint.h>

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
  printf("%-73s", description);
  fflush(stdout);
  int err = (*test_fun)();
  if(err) {
    printf("FAILED\n");
    printf("Fail in: %s: %d\n", description, err);
  } else {
    printf("PASSED\n");
  }
  return err;
}

/*
 * Picks and returns a random integer between lower (including) and
 * upper (excluding). DON'T USE THIS IF YOU NEED YOUR RANDOM NUMBERS
 * TO BE EQUALLY DISTRIBUTED. This is really just for testing.
 */
uint64_t randomint(uint64_t lower, uint64_t upper) {
  uint64_t result = 0;
  if (upper <= lower) return 0;
  uint64_t delta = upper - lower;
  unsigned char bytes[8];
  // Sample all bytes at once to speed up the process.
  randombytes(bytes, 8);
  int i = 0;
  for(; delta > 0; i++) {
    unsigned char randombyte = bytes[i];
    if (delta < 256)
      randombyte = randombyte % delta;
    result += (randombyte << (i * 8));
    delta >>= 8;
  }
  result += lower;
  return result;
}

void hexdump(unsigned char *data, int start, int len)
{
  int i;
  for(i = start; i < start + len; i++) {
    if(i % 32 == 0) printf("%04d: ", i);
    printf("%02x", data[i]);
    if(i % 2) printf(" ");
    if((i + 1) % 32 == 0) printf("\n");
  }
  // Make sure to print a newline unless we just printed one
  if(i % 32 != 0) printf("\n");
}
