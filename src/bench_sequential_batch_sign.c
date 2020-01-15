#include <stdio.h>
#include "sequential_batch_sign.h"
#include "testutils.h"
#include "benchutils.h"
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

  print_bytes("crypto_secretkeybytes", CRYPTO_SECRETKEYBYTES);
  print_bytes("crypto_publickeybytes", CRYPTO_PUBLICKEYBYTES);
  print_bytes("crypto_sts_bytes", CRYPTO_STS_BYTES);
  print_bytes("crypto_bytes", CRYPTO_BYTES);

  {
    unsigned long start = GetCC();
    crypto_sign_keypair(pk, sk);
    unsigned long end = GetCC();
    print_cycles("Keypair", start, end);
  }

  unsigned char sts[CRYPTO_STS_BYTES];
  unsigned long long clen;

  int res = 0;
  {
    unsigned long start = GetCC();
    res |= crypto_sts_init(sts, &clen, sk, -1);
    if(res != 0) return res;
    unsigned long end = GetCC();
    print_cycles("STS init", start, end);
  }

  unsigned char sm[CRYPTO_BYTES + mlen];
  unsigned long long slen;

  {
    unsigned long start = GetCC();
    int i;
    for(i = 0; i < (1 << SUBTREE_HEIGHT); i++) {
      slen = 0;
      res |= crypto_sts_sign(message, mlen, sts, &clen, sm, &slen, sk);
      if(res != 0) return res;
    }
    unsigned long end = GetCC();
    print_cycles("Sign", start, end);
  }

  {
    unsigned long start = GetCC();
    res |= crypto_sign_open(message, &mlen, sm, slen, pk);
    unsigned long end = GetCC();
    print_cycles("Verify", start, end);
  }


  unsigned long end_count = GetCC();
  print_cycles("Elapsed cycles", start_count, end_count);
  return res;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&bench, "Benchmark SPHINCS sequential batch signatures");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
