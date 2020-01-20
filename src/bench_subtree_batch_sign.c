#include <stdio.h>
#include "subtree_batch_sign.h"
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

  int res = 0;
  {
    unsigned long start = GetCC();
    res |= crypto_sts_init(sts, sk, -1);
    if(res != 0) return res;
    unsigned long end = GetCC();
    print_cycles("STS init", start, end);
  }

  unsigned char sm1[CRYPTO_BYTES + mlen];
  unsigned long long slen1;

  {
    unsigned long start = GetCC();
    int i;
    for(i = 0; i < (1 << STS_SUBTREE_HEIGHT); i++) {
      res |= crypto_sts_sign(sm1, &slen1, message, mlen, sts, sk);
      if(res != 0) return res;
    }
    unsigned long end = GetCC();
    char desc[24];
    snprintf(desc, sizeof(desc), "Sign, %d signatures", 1<<STS_SUBTREE_HEIGHT);
    print_cycles(desc, start, end);
    // Print an average cycle count per signature
    unsigned long total = end - start;
    double avg = (double) total / (double)(1<<STS_SUBTREE_HEIGHT);
    print_cycles("Sign, avg per signature", start, start + avg);
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

  err |= run_bench(&bench, "Benchmark SPHINCS subtree batch signatures");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
