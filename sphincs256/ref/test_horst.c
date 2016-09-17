#include <stdio.h>
#include "prg.h"
#include "horst.h"
#include "params.h"

int compare(unsigned char *x, unsigned char *y, unsigned long long l)
{
  int i;
  for (i = 0; i < l; ++i)
  {
    if(x[i] != y[i]) return 1;
  }
  return 0;
}

int test01() {
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
  // Fill remainder with 0s
  for (; i < mlen; ++i) { message[i] = 0; }
  
  unsigned char sig[HORST_SIGBYTES];
  unsigned char pk[HASH_BYTES];
  unsigned long long sigbytes;

  // Initialize a not-so-random seed
  unsigned char seed[SEED_BYTES];
  for (i = 0; i < SEED_BYTES; ++i) { seed[i] = 0; }
  prg(seed, SEED_BYTES, seed);

  // construct mask
  unsigned int masklen = 2*HORST_LOGT*HASH_BYTES;
  unsigned char masks[masklen];
  prg(masks, masklen, seed);

  // Hash message
  unsigned char m_hash[MSGHASH_BYTES];
  msg_hash(m_hash, message, mlen);
  
  horst_sign(
    sig,
    pk,
    &sigbytes, 
    message, mlen, 
    seed, 
    masks, 
    m_hash
  );

  int res = horst_verify(
    pk,
    sig,
    message,
    mlen,
    masks,
    m_hash
  );


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

