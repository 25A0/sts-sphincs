#include "sign.h"

int main(int nargs, char** args)
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  // Create a keypair
  crypto_sign_keypair(pk, sk);

  unsigned long long mlen = 32;
  unsigned char message[mlen + CRYPTO_BYTES];
  unsigned int i = 0;
  for (; i < mlen; ++i) { message[i] = i; }

  unsigned char sm[CRYPTO_BYTES + mlen];
  unsigned long long slen;

  // Sign the message
  int res = crypto_sign(sm, &slen, message, mlen, sk);
  if(res != 0) return res;

  // Verify the signature
  res = crypto_sign_open(message, &mlen, sm, slen, pk);
  if(res != 0) return res;

  return 0;
}
