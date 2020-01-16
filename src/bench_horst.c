#include <stdio.h>
#include "horst.h"
#include "params.h"
#include "hash.h"
#include "hash_address.h"
#include "randombytes.h"
#include "benchutils.h"

static __inline__ unsigned long GetCC(void)
{
  unsigned a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((unsigned long)a) | (((unsigned long)d) << 32);
}

struct result {
  unsigned long sign;
  unsigned long verify;
};

int bench(struct result *results)
{
  unsigned char sig[HORST_SIGBYTES];
  unsigned long long sigbytes;

  // Generate keypair
  unsigned char pk[HASH_BYTES];
  unsigned char seed[SEED_BYTES];
  randombytes(seed, SEED_BYTES);

  unsigned char addr[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    addr[i] = 0;
  }

  unsigned long long mlen = 32;
  unsigned char message[mlen];
  randombytes(message, mlen);

  // Hash message
  unsigned char m_hash[MSGHASH_BYTES];
  msg_hash(m_hash, message, mlen);

  {
    unsigned long start = GetCC();
    horst_sign(sig, pk, &sigbytes, seed, addr, m_hash, MSGHASH_BYTES);
    unsigned long end = GetCC();
    results->sign = end - start;
  }

  unsigned char gpk[HASH_BYTES];

  {
    unsigned long start = GetCC();
    int res = horst_verify(gpk, sig, addr, m_hash, MSGHASH_BYTES);
    unsigned long end = GetCC();
    results->verify = end - start;
    if (res != 0) {
      return res;
    }
  }

  return compare(pk, gpk, HASH_BYTES);

}

int main(int argc, char const *argv[])
{
  print_bytes("horst_sigbytes", HORST_SIGBYTES);
  int n_samples = 32;

  // Accumulate the results here, average later
  struct result avg = {};

  int i = 0;
  for(; i < n_samples; i++) {
    struct result res = {};
    int err = bench(&res);
    avg.sign += res.sign;
    avg.verify += res.verify;
    if(err)
    {
      printf("Expected and actual results differed. %d\n", err);
      return err;
    }
  }

  avg.sign /= n_samples;
  avg.verify /= n_samples;

  print_cycles("Sign", 0, avg.sign);
  print_cycles("Verify", 0, avg.verify);

  return 0;
}
