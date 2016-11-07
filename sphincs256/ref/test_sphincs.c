#include <stdio.h>
#include "sign.h"
#include "api.h"
#include "testutils.h"

int test01()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
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
  
  unsigned char sm[CRYPTO_BYTES + mlen];

  crypto_sign_keypair(pk, sk);

  unsigned long long smlen;
  crypto_sign(sm, &smlen,
              message, mlen,
              sk);

  int res = crypto_sign_open(message, &mlen,
                             sm, smlen,
                             pk);
  return res;
}

int test02()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
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

  crypto_sign_keypair(pk, sk);

  unsigned char context[CRYPTO_CONTEXTBYTES];
  unsigned long long clen;

  unsigned char seed[SEED_BYTES];
  randombytes(seed, SEED_BYTES);

  int res = crypto_context_init(context, &clen, sk, seed);
  if(res != 0) return res;

  unsigned char sm[CRYPTO_BYTES + mlen];

  unsigned long long slen;
  res = crypto_sign_full(message, mlen, context, &clen, sm, &slen, sk);
  if(res != 0) return res;

  res = crypto_sign_open(message, &mlen, sm, slen, pk);

  return res;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test SPHINCS signing and verifying");
  err |= run_test(&test02, "Test SPHINCS batch signing and verifying");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
