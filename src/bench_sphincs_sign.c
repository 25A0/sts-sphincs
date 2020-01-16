#include <stdio.h>
#include "sign.h"
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
  print_bytes("crypto_bytes", CRYPTO_BYTES);

  {
    unsigned long start = GetCC();
    crypto_sign_keypair(pk, sk);
    unsigned long end = GetCC();
    print_cycles("Keypair", start, end);
  }

  int res = 0;

  unsigned char sm1[CRYPTO_BYTES + mlen];
  unsigned long long slen1;

  {
    unsigned long start = GetCC();
    int i;
    for(i = 0; i < (1 << SUBTREE_HEIGHT); i++) {
      res |= crypto_sign(sm1, &slen1, message, mlen, sk);
      if(res != 0) return res;
    }
    unsigned long end = GetCC();
    print_cycles("Sign", start, end);
  }

  // Both signatures should verify
  {
    unsigned long start = GetCC();
    res |= crypto_sign_open(message, &mlen, sm1, slen1, pk);
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

  err |= run_bench(&bench, "Benchmark SPHINCS signatures");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
