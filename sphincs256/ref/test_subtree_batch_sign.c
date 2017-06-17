#include <stdio.h>
#include "sign.h"
#include "api.h"
#include "subtree_batch_api.h"
#include "batch_sign.h"
#include "testutils.h"
#include "randombytes.h"

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

  crypto_sign_keypair(pk, sk);

  unsigned char context[CRYPTO_CONTEXTBYTES];
  unsigned long long clen;

  int res = crypto_context_init(context, &clen, sk, -1);
  if(res != 0) return res;

  unsigned char sm[CRYPTO_BYTES + mlen];

  unsigned long long slen;
  res = crypto_sign_full(message, mlen, context, &clen, sm, &slen, sk);
  if(res != 0) return res;

  res = crypto_sign_open_full(message, &mlen, sm, slen, pk);

  return res;
}

int test02()
{
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
  unsigned char sm2[CRYPTO_BYTES + mlen];
  unsigned long long slen2;

  res |= crypto_sign_full(message, mlen, context, &clen, sm1, &slen1, sk);
  if(res != 0) return res;
  res |= crypto_sign_full(message, mlen, context, &clen, sm2, &slen2, sk);
  if(res != 0) return res;

  // The length of both signatures should be the same
  if(slen1 != slen2) return -1;

  // Make sure that the signatures are not identical
  int eq = compare(sm1, sm2, slen1);
  if(!eq) return -2;

  // Both signatures should verify
  res |= crypto_sign_open(message, &mlen, sm1, slen1, pk);
  res |= crypto_sign_open(message, &mlen, sm2, slen2, pk) << 1;

  return res;
}

int test03()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char context[CRYPTO_CONTEXTBYTES];
  unsigned long long clen;

  // This number is exactly 1 larger than the largest valid subtree index
  long long subtree_idx = (long long) 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT);

  int res = 0;
  res |= crypto_context_init(context, &clen, sk, subtree_idx);
  // Since we passed an invalid subtree index, we expect the result to be
  // negative.
  if(res >= 0) return -1;
  else return 0;
}

int test04()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char context_a[CRYPTO_CONTEXTBYTES];
  unsigned long long clen_a;
  unsigned char context_b[CRYPTO_CONTEXTBYTES];
  unsigned long long clen_b;

  // A random, but valid subtree index
  long long upper = (long long) 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT);
  long long subtree_idx = randomint(0, upper);

  int res = 0;
  res |= crypto_context_init(context_a, &clen_a, sk, subtree_idx);
  if(res != 0) return -1;
  res |= crypto_context_init(context_b, &clen_b, sk, subtree_idx);
  if(res != 0) return -1;
  if(clen_a != clen_b) return -1;
  return compare(context_a, context_b, clen_a);
}

int test05()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char context_a[CRYPTO_CONTEXTBYTES];
  unsigned long long clen_a;
  unsigned char context_b[CRYPTO_CONTEXTBYTES];
  unsigned long long clen_b;

  int res = 0;
  res |= crypto_context_init(context_a, &clen_a, sk, -1);
  if(res != 0) return -1;
  res |= crypto_context_init(context_b, &clen_b, sk, -1);
  if(res != 0) return -1;
  if(clen_a != clen_b) return -1;
  // Since we chose a random subtree each time, the context should not
  // be the same.
  return ! compare(context_a, context_b, clen_a);
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test SPHINCS subtree batch signing and verifying");
  err |= run_test(&test02, "Test two SPHINCS batch signatures");
  err |= run_test(&test03, "Test that invalid subtree index is rejected");
  err |= run_test(&test04, "Test that context is deterministic with chosen subtree index");
  err |= run_test(&test05, "Test that context is non-deterministic with random subtree index");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
