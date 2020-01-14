#ifndef SIGN_H
#define SIGN_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      HORST_SIGBYTES + \
                      (TOTALTREE_HEIGHT/SUBTREE_HEIGHT)*WOTS_SIGBYTES + \
                      TOTALTREE_HEIGHT*HASH_BYTES)
#define CRYPTO_DETERMINISTIC 1

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen, 
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m,unsigned long long *mlen, 
                     const unsigned char *sm,unsigned long long smlen,
                     const unsigned char *pk);

const unsigned char* get_public_seed_from_pk(const unsigned char* pk);

const unsigned char* get_public_seed_from_sk(const unsigned char* sk);

#endif
