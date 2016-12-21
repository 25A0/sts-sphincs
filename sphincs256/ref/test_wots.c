#include <stdio.h>
#include "api.h"
#include "randombytes.h"
#include "wots.h"
#include "testutils.h"

int test01()
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

  wots_pkgen(pk, sk, seed, addr);

  // Message
  // wots will always sign hashes, so we use a message
  // of length HASH_BYTES here.
  unsigned long long mlen = HASH_BYTES;
  unsigned char message[mlen];

  message[i++] = 'H';
  message[i++] = 'e';
  message[i++] = 'l';
  message[i++] = 'l';
  message[i++] = 'o';
  message[i++] = ' ';
  message[i++] = 'W';
  message[i++] = 'o';
  message[i++] = 'r';
  message[i++] = 'l';
  message[i++] = 'd';
  message[i++] = '!';
  for (; i < mlen; ++i) { message[i] = 0; }

  // Create signature
  unsigned char sig[WOTS_L*HASH_BYTES];

  wots_sign(sig, message, sk, seed, addr);

  // Verify signature

  // Generated pk:
  unsigned char gpk[WOTS_L*HASH_BYTES];

  wots_verify(gpk, sig, message, seed, addr);

  return compare(pk, gpk, WOTS_L*HASH_BYTES);
}

int test02()
{
  unsigned char sk[HASH_BYTES];
  randombytes(sk, HASH_BYTES);

  unsigned char seed[PUBLIC_SEED_BYTES];
  randombytes(seed, PUBLIC_SEED_BYTES);

  unsigned char addr[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    addr[i] = 0;
  }
  set_type(addr, WOTS_ADDR);
  set_wots_ots_index(addr, 0);

  unsigned char out[HASH_BYTES];
  int err = 0;
  gen_chain(out,
            sk,
            seed,
            addr,
            WOTS_W - 1,
            0);
  for(i = 0; i < WOTS_W - 1; i++) {
    unsigned char buf[HASH_BYTES];
    gen_chain(buf, sk, seed, addr, i, 0);
    gen_chain(buf, buf, seed, addr, WOTS_W - 1 - i, i);
    err |= compare(out, buf, HASH_BYTES);
  }

  return err;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test WOTS as a whole");
  err |= run_test(&test02, "Test chaining function");

  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}
