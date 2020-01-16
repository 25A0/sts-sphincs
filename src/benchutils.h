#ifndef BENCHUTILS_H
#define BENCHUTILS_H

int compare(unsigned char *x, unsigned char *y, unsigned long long l);

int run_bench(int (*test_fun)(void), char* description);

void print_cycles(const char* desc, unsigned long start, unsigned long end);

void print_bytes(const char* desc, unsigned long bytes);

#endif
