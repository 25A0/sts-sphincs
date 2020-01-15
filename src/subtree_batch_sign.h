#ifndef SUBTREE_BATCH_SIGN_H
#define SUBTREE_BATCH_SIGN_H

#include "params.h"
#include <stdint.h>

// When changing the subtree height, make sure that the type used for the
// subtree height index is still large enough to capture all indices.
// That is, ensure that SUBTREE_HEIGHT < sizeof(TSUBTREE_IDX) * 8
typedef uint8_t TSUBTREE_IDX;

// To sign 64 Bytes with WOTS_LOGW = 4, L1 is (64 * 8)/4 = 128.
// Accordingly, l2 is ceil(ceil(log_2(128 * (16 - 1)))/4) = 3
#define STS_WOTS_L     131
#define STS_WOTS_L1    128
#define STS_WOTS_LOG_L   7
#define STS_WOTS_SIGBYTES (STS_WOTS_L * HASH_BYTES)

#define STS_HORST_K 16
#define STS_HORST_SIGBYTES (64*HASH_BYTES+(((HORST_LOGT-6)*HASH_BYTES)+\
                                           HORST_SKBYTES)*STS_HORST_K)

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + \
                               SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      STS_HORST_SIGBYTES +                              \
                      STS_WOTS_SIGBYTES +                               \
                      (N_LEVELS - 1)*WOTS_SIGBYTES +                    \
                      HASH_BYTES * (TOTALTREE_HEIGHT - SUBTREE_HEIGHT + \
                                    SUBTREE_HEIGHT))
#define CRYPTO_DETERMINISTIC 1

#define CRYPTO_STS_BYTES    (SEED_BYTES + sizeof(TSUBTREE_IDX) +        \
                             (TOTALTREE_HEIGHT + 7) / 8 +               \
                             (1<<SUBTREE_HEIGHT) * HASH_BYTES +         \
                             STS_HORST_SIGBYTES +                       \
                             N_LEVELS * WOTS_SIGBYTES +                 \
                             (TOTALTREE_HEIGHT - SUBTREE_HEIGHT) * HASH_BYTES)

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
