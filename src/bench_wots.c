#include <stdio.h>
#include "wots.h"
#include "benchutils.h"
#include "randombytes.h"

static __inline__ unsigned long GetCC(void)
{
  unsigned a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((unsigned long)a) | (((unsigned long)d) << 32);
}

struct result {
  unsigned long keypair;
  unsigned long sign;
  unsigned long verify;
};

int bench(struct result *results)
{
  // Generate keypair
  unsigned char pk[WOTS_L*HASH_BYTES];
  unsigned char sk[SEED_BYTES];
  unsigned char seed[PUBLIC_SEED_BYTES];
  randombytes(seed, PUBLIC_SEED_BYTES);
  randombytes(sk, SEED_BYTES);

  unsigned char addr[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    addr[i] = 0;
  }

  {
    unsigned long start = GetCC();
    wots_pkgen(pk, sk, seed, addr);
    unsigned long end = GetCC();
    results->keypair = end - start;
  }

  // Message
  // wots will always sign hashes, so we use a message
  // of length HASH_BYTES here.
  unsigned long long mlen = HASH_BYTES;
  unsigned char message[mlen];
  randombytes(message, mlen);

  // Create signature
  unsigned char sig[WOTS_L*HASH_BYTES];

  {
    unsigned long start = GetCC();
    wots_sign(sig, message, sk, seed, addr);
    unsigned long end = GetCC();
    results->sign = end - start;
  }

  // Verify signature

  // Generated pk:
  unsigned char gpk[WOTS_L*HASH_BYTES];

  {
    unsigned long start = GetCC();
    wots_verify(gpk, sig, message, seed, addr);
    unsigned long end = GetCC();
    results->verify = end - start;
  }

  return compare(pk, gpk, WOTS_L*HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  print_bytes("wots_sigbytes", WOTS_SIGBYTES);
  int n_samples = 32;

  // Accumulate the results here, average later
  struct result avg = {};

  int i = 0;
  for(; i < n_samples; i++) {
    struct result res = {};
    int err = bench(&res);
    avg.keypair += res.keypair;
    avg.sign += res.sign;
    avg.verify += res.verify;
    if(err)
    {
      printf("Expected and actual results differed. %d\n", err);
      return err;
    }
  }

  avg.keypair /= n_samples;
  avg.sign /= n_samples;
  avg.verify /= n_samples;

  print_cycles("Keypair", 0, avg.keypair);
  print_cycles("Sign", 0, avg.sign);
  print_cycles("Verify", 0, avg.verify);

  return 0;
}
