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

int bench()
{
  unsigned long start_count = GetCC();
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
  randombytes(message, mlen);

  crypto_sign_keypair(pk, sk);

  unsigned char context[CRYPTO_CONTEXTBYTES];
  unsigned long long clen;

  int res = 0;
  res |= crypto_context_init(context, &clen, sk, -1);
  if(res != 0) return res;

  unsigned char sm1[CRYPTO_BYTES + mlen];
  unsigned long long slen1;

  res |= crypto_sign_full(message, mlen, context, &clen, sm1, &slen1, sk);
  if(res != 0) return res;

  // Both signatures should verify
  res |= crypto_sign_open(message, &mlen, sm1, slen1, pk);

  unsigned long end_count = GetCC();
  printf("Elapsed cycles: %lu\n", end_count - start_count);
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
