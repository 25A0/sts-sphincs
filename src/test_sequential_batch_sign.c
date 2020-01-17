#include <stdio.h>
#include "sequential_batch_sign.h"
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

  unsigned char sts[CRYPTO_STS_BYTES];

  int res = crypto_sts_init(sts, sk, -1);
  if(res != 0) return res;

  unsigned char sm[CRYPTO_BYTES + mlen];

  unsigned long long slen;
  res = crypto_sts_sign(sm, &slen, message, mlen, sts, sk);
  if(res != 0) return res;

  res = crypto_sign_open(message, &mlen, sm, slen, pk);

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

  unsigned char sts[CRYPTO_STS_BYTES];

  int res = 0;
  res |= crypto_sts_init(sts, sk, -1);
  if(res != 0) return res;

  unsigned char sm1[CRYPTO_BYTES + mlen];
  unsigned long long slen1;
  unsigned char sm2[CRYPTO_BYTES + mlen];
  unsigned long long slen2;

  res |= crypto_sts_sign(sm1, &slen1, message, mlen, sts, sk);
  if(res != 0) return res;
  res |= crypto_sts_sign(sm2, &slen2, message, mlen, sts, sk);
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

  unsigned char sts[CRYPTO_STS_BYTES];

  // This number is exactly 1 larger than the largest valid leaf index
  long long subtree_idx = (long long) 1 << (TOTALTREE_HEIGHT);

  int res = 0;
  res |= crypto_sts_init(sts, sk, subtree_idx);
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

  unsigned char sts_a[CRYPTO_STS_BYTES];
  unsigned char sts_b[CRYPTO_STS_BYTES];

  // A random, but valid leaf index
  long long upper = (long long) 1 << TOTALTREE_HEIGHT;
  long long subtree_idx = randomint(0, upper);

  int res = 0;
  res |= crypto_sts_init(sts_a, sk, subtree_idx);
  if(res != 0) return -12;
  res |= crypto_sts_init(sts_b, sk, subtree_idx);
  if(res != 0) return -13;
  return compare(sts_a, sts_b, CRYPTO_STS_BYTES);
}

int test05()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char sts_a[CRYPTO_STS_BYTES];
  unsigned char sts_b[CRYPTO_STS_BYTES];

  int res = 0;
  res |= crypto_sts_init(sts_a, sk, -1);
  if(res != 0) return -1;
  res |= crypto_sts_init(sts_b, sk, -1);
  if(res != 0) return -1;
  // Since we chose a random leaf each time, the STS should not
  // be the same.
  return ! compare(sts_a, sts_b, CRYPTO_STS_BYTES);
}

int test06()
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

int test07()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char sts[CRYPTO_STS_BYTES];

  int res = 0;
  res |= crypto_sts_init(sts, sk, -1);
  if(res != 0) return -1;

  // Right after creating the STS, there should be a full subtree of remaining uses
  long long remaining_uses;
  remaining_uses = crypto_sts_remaining_uses(sts);
  if(remaining_uses != (1 << SUBTREE_HEIGHT)) return -1;

  // Now we sign a message
  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
  randombytes(message, mlen);

  unsigned char sm[CRYPTO_BYTES + mlen];

  unsigned long long smlen;
  crypto_sts_sign(sm, &smlen, message, mlen, sts, sk);

  // And after that we should have one fewer remaining uses
  remaining_uses = crypto_sts_remaining_uses(sts);
  if(remaining_uses != (1 << SUBTREE_HEIGHT) - 1) return -1;

  return 0;
}

int test08()
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char sts[CRYPTO_STS_BYTES];

  int res = crypto_sts_init(sts, sk, 3);
  if(res != 0) return res;

  int n_samples = 1<<SUBTREE_HEIGHT;
  int i;
  for(i = 0; i < n_samples; i++) {
    unsigned long long mlen = 32;
    unsigned char message[mlen + CRYPTO_BYTES];
    randombytes(message, mlen);

    unsigned char sm[CRYPTO_BYTES + mlen];
    unsigned long long slen = 0;

    // Check that the # of remaining uses is correct:
    if(crypto_sts_remaining_uses(sts) != n_samples - i) {
      printf("Expected: %d Actual: %lld\n", n_samples - i, crypto_sts_remaining_uses(sts));
      return -15;
    }
    res = crypto_sts_sign(sm, &slen, message, mlen, sts, sk);
    if(res != 0) return res;
    res = crypto_sign_open(message, &mlen, sm, slen, pk);
    if(res != 0) return res;
    if(crypto_sts_remaining_uses(sts) != n_samples - i - 1) {
      printf("Expected: %d Actual: %lld\n", n_samples - i - 1, crypto_sts_remaining_uses(sts));
      return -16;
    }
  }

  // After this, exactly 0 uses should be left
  if(crypto_sts_remaining_uses(sts) != 0) return -17;

  return res;
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test SPHINCS batch signing and verifying");
  err |= run_test(&test02, "Test two SPHINCS batch signatures");
  err |= run_test(&test03, "Test that invalid leaf index is rejected");
  err |= run_test(&test04, "Test that STS is deterministic with chosen leaf index");
  err |= run_test(&test05, "Test that STS is non-deterministic with random leaf index");
  err |= run_test(&test06, "Test classic API with sequential batch signing");
  err |= run_test(&test07, "Test remainig uses");
  err |= run_test(&test08, "Test a full subtree of signatures");

  if(err)
  {
    printf("Expected and actual results differed. %d\n", err);
  }
  return err;
}
