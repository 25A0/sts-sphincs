#include <stdio.h>
#include "prg.h"
#include "horst.h"
#include "params.h"
#include "hash.h"
#include "hash_address.h"
#include "testutils.h"

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

  // construct address
  unsigned char addr[ADDR_BYTES];
  for(i = 0; i < ADDR_BYTES; i++) {
    addr[i] = 0;
  }

  // Hash message
  unsigned char m_hash[MSGHASH_BYTES];
  msg_hash(m_hash, message, mlen);
  
  horst_sign(
    sig,
    pk,
    &sigbytes, 
    message, mlen, 
    seed, 
    addr,
    m_hash
  );

  unsigned char gpk[HASH_BYTES];
  int res = horst_verify(
    gpk,
    sig,
    message,
    mlen,
    addr,
    m_hash
  );

  if (res != 0) {
    return res;
  }
  else return compare(pk, gpk, HASH_BYTES);
}

int test02() {
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

  // construct address
  unsigned char addr[ADDR_BYTES];

  // Choose a random address
  randombytes(addr, ADDR_BYTES);

  // Hash message
  unsigned char m_hash[MSGHASH_BYTES];
  msg_hash(m_hash, message, mlen);
  
  horst_sign(
    sig,
    pk,
    &sigbytes, 
    message, mlen, 
    seed, 
    addr,
    m_hash
  );

  unsigned char gpk[HASH_BYTES];
  int res = horst_verify(
    gpk,
    sig,
    message,
    mlen,
    addr,
    m_hash
  );

  if (res != 0) {
    return res;
  }
  else return compare(pk, gpk, HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  int err = 0;
  
  err |= test01();
  err |= test02();
  
  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}

