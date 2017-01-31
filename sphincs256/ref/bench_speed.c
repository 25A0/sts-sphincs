#include <stdio.h>
#include <stdlib.h>
#include "sign.h"
#include "api.h"
#include "testutils.h"
#include "randombytes.h"
#include <string.h>

long int NUM_TESTS = 10;

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

  int res = 0;
  unsigned long long smlen;
  for(i = 0; i < NUM_TESTS; i++) {
    res |= crypto_sign(sm, &smlen,
                message, mlen,
                sk);
  }

  // We only care about the signing time here. No point in timing the
  // verifications.

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
  for(i = 0; i < NUM_TESTS; i++) {
    res |= crypto_sign_full(message, mlen, context, &clen, sm, &slen, sk);
  }

  return res;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  if(argc < 2) {
    printf("Usage: %s test [count]\n", argv[0]);
    exit(1);
  }
  if(argc > 2) {
    const char* str = argv[2];
    char* endstr;
    long int parsed_count = strtol(str, &endstr, 10);
    if(str != endstr)
      NUM_TESTS = parsed_count;
  }

  if(strncmp(argv[1], "1", 1) == 0) {
    char description[128];
    snprintf(description, 128, "Benchmarking speed of %ld original SPHINCS signatures",
            NUM_TESTS);
    err |= run_test(&test01, description);
  } else if(strncmp(argv[1], "2", 1) == 0) {
    char description[128];
    snprintf(description, 128, "Benchmarking speed of %ld batch SPHINCS signatures",
            NUM_TESTS);
    err |= run_test(&test02, description);
  }

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
