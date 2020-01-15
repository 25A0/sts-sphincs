#ifndef SEQUENTIAL_BATCH_SIGN_H
#define SEQUENTIAL_BATCH_SIGN_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      HORST_SIGBYTES +                                  \
                      (TOTALTREE_HEIGHT/SUBTREE_HEIGHT)*WOTS_SIGBYTES + \
                      TOTALTREE_HEIGHT*HASH_BYTES)
#define CRYPTO_DETERMINISTIC 1

#define CRYPTO_STS_BYTES    ((TOTALTREE_HEIGHT+7)/8 +                   \
                             (1 << SUBTREE_HEIGHT) * HASH_BYTES +       \
                             (N_LEVELS - 1) * (WOTS_SIGBYTES + \
                                               SUBTREE_HEIGHT * HASH_BYTES))

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

/* Initialize a new short-time state (STS) based on the given secret key.
 * If a negative value is passed as the subtree index (subtree_idx),
 * a random subtree will be used.
 * If a subtree index between 0 and 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT)
 * is passed, then that index will be used. The initialization will fail
 * with values larger than 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT).
 */
int crypto_sts_init(unsigned char *sts, unsigned long long *clen,
                        const unsigned char *sk, long long subtree_idx);

int crypto_sts_sign(const unsigned char *m, unsigned long long mlen,
                    unsigned char *sts, unsigned long long *clen,
                    unsigned char *sig, unsigned long long *slen,
                    const unsigned char *sk);

#endif
