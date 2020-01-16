#ifndef TESTUTILS
#define TESTUTILS

// compares the two arrays
int compare(unsigned char *x, unsigned char *y, unsigned long long l);

// runs the given function.
// if the function returns something other than 0, it is assumed
// that the underlying test failed, and the description will be printed
int run_test(int (*test_fun)(void), char* description);

int run_bench(int (*test_fun)(void), char* description);

int randomint(int lower, int upper);

void hexdump(unsigned char *data, int start, int len);

#endif
