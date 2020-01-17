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

/*
  The short-time state consists of:
   - the index of the leaf that was randomly chosen when the STS was initialized
   - the number of signatures that have already been signed with this STS
   - The (1<<SUBTREE_HEIGHT) WOTS public keys in this subtree
   - The WOTS signatures and authentication paths for the other layers of the hypertree

*/
#define CRYPTO_STS_BYTES    (sizeof(unsigned long long) +               \
                             sizeof(unsigned long long) +               \
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
 * If a negative value is passed as the leaf index (leaf_idx),
 * a random leaf will  be used.
 * If a leaf index between 0 and 1 << TOTALTREE_HEIGHT
 * is passed, then that index will be used. The initialization will fail
 * with values larger than 1 << TOTALTREE_HEIGHT.
 */
int crypto_sts_init(unsigned char *sts, const unsigned char *sk, long long leaf_idx);

int crypto_sts_sign(unsigned char *sig, unsigned long long *slen,
                    const unsigned char *m, unsigned long long mlen,
                    unsigned char *sts,
                    const unsigned char *sk);

long long crypto_sts_remaining_uses(unsigned char *sts);

#endif
