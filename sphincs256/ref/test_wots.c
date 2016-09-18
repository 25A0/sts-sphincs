#include <stdio.h>
#include "api.h"
#include "randombytes.h"
#include "wots.h"

int compare(unsigned char *x, unsigned char *y, unsigned long long l)
{
  int i;
  for (i = 0; i < l; ++i)
  {
    if(x[i] != y[i]) return 1;
  }
  return 0;
}

int test01()
{
  // Generate keypair
  unsigned char pk[WOTS_L*HASH_BYTES];
  unsigned char sk[SEED_BYTES];
  unsigned char masks[(WOTS_W-1)*HASH_BYTES];
  randombytes(masks, (WOTS_W-1)*HASH_BYTES);
  wots_pkgen(pk, sk, masks);

  // Message
  // wots will always sign hashes, so we use a message
  // of length HASH_BYTES here.
  unsigned long long mlen = HASH_BYTES;
  unsigned char message[mlen];
  unsigned int i = 0;
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

  wots_sign(sig, message, sk, masks);

  // Verify signature

  // Generated pk:
  unsigned char gpk[WOTS_L*HASH_BYTES];

  wots_verify(gpk, sig, message, masks);

  return compare(pk, gpk, WOTS_L*HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  int err = 0;
  
  err |= test01();
  
  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}
