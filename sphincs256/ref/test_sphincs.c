#include <stdio.h>
#include "sign.h"
#include "api.h"

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
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned long long mlen = 32;
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
