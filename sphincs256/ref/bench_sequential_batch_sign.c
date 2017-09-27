#include <stdio.h>
#include "sign.h"
#include "api.h"
#include "sequential_batch_api.h"
#include "batch_sign.h"
#include "testutils.h"
#include "randombytes.h"

static __inline__ unsigned long GetCC(void)
{
  unsigned a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((unsigned long)a) | (((unsigned long)d) << 32);
}

void print_elapsed(const char* desc, unsigned long start, unsigned long end)
{
  printf("%s: %lu\n", desc, end - start);
}

int bench()
{
  unsigned long start_count = GetCC();
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
  randombytes(message, mlen);

  printf("crypto_secretkeybytes: %d\n", CRYPTO_SECRETKEYBYTES);
  printf("crypto_publickeybytes: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("crypto_contextbytes:   %d\n", CRYPTO_CONTEXTBYTES);
  printf("crypto_bytes:          %d\n", CRYPTO_BYTES);

  {
    unsigned long start = GetCC();
    crypto_sign_keypair(pk, sk);
    unsigned long end = GetCC();
    print_elapsed("Keypair", start, end);
  }

  unsigned char context[CRYPTO_CONTEXTBYTES];
  unsigned long long clen;

  int res = 0;
  {
    unsigned long start = GetCC();
    res |= crypto_context_init(context, &clen, sk, -1);
    if(res != 0) return res;
    unsigned long end = GetCC();
    print_elapsed("Context init", start, end);
  }

  unsigned char sm[CRYPTO_BYTES + mlen];
  unsigned long long slen;

  {
    unsigned long start = GetCC();
    int i;
    for(i = 0; i < (1 << SUBTREE_HEIGHT); i++) {
      slen = 0;
      res |= crypto_sign_full(message, mlen, context, &clen, sm, &slen, sk);
      if(res != 0) return res;
    }
    unsigned long end = GetCC();
    print_elapsed("Sign", start, end);
  }

  {
    unsigned long start = GetCC();
    res |= crypto_sign_open_full(message, &mlen, sm, slen, pk);
    unsigned long end = GetCC();
    print_elapsed("Verify", start, end);
  }


  unsigned long end_count = GetCC();
  print_elapsed("Elapsed cycles", start_count, end_count);
  return res;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&bench, "Benchmark SPHINCS batch signatures");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}