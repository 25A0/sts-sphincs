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

/*
 * The signature consists of:
 *  - the message hash seed
 *  - the index of the HORST key pair that was used to sign the subtree nodes
 *  - the HORST signature that signs the subtree nodes
 *  - the WOTS signature of the message
 *  - one WOTS signature for each level of the hypertree except for the lowest
 *    subtree, in which a message is signed
 *  - the authentication path through the entire hypertree
 */

// Sizes of signature elements
#define SIZEOF_SIG_LEAFIDX sizeof(unsigned long long)
#define SIZEOF_SIG_SUBTREE_LEAFIDX sizeof(unsigned long long)
#define SIZEOF_SIG_MESSAGE_HASH_SEED MESSAGE_HASH_SEED_BYTES
#define SIZEOF_SIG_WOTS_MESSAGE_SIGNATURE STS_WOTS_SIGBYTES
#define SIZEOF_SIG_SUBTREE_AUTHPATH (SUBTREE_HEIGHT * HASH_BYTES)
#define SIZEOF_SIG_HORST_SIGNATURE STS_HORST_SIGBYTES
#define SIZEOF_SIG_WOTS_SIGNATURES_AND_AUTHPATHS ((N_LEVELS - 1) *          \
                                              (WOTS_SIGBYTES +          \
                                               HASH_BYTES * SUBTREE_HEIGHT))

// Offsets of signature elements. These determine the order of the elements.
// The offset of the element is the offset of the previous element plus
// the size of the previous element
#define OFFSET_SIG_LEAFIDX \
  0
#define OFFSET_SIG_SUBTREE_LEAFIDX \
  OFFSET_SIG_LEAFIDX + SIZEOF_SIG_LEAFIDX
#define OFFSET_SIG_MESSAGE_HASH_SEED \
  OFFSET_SIG_SUBTREE_LEAFIDX + SIZEOF_SIG_SUBTREE_LEAFIDX
#define OFFSET_SIG_WOTS_MESSAGE_SIGNATURE \
  OFFSET_SIG_MESSAGE_HASH_SEED + SIZEOF_SIG_MESSAGE_HASH_SEED
#define OFFSET_SIG_SUBTREE_AUTHPATH \
  OFFSET_SIG_WOTS_MESSAGE_SIGNATURE + SIZEOF_SIG_WOTS_MESSAGE_SIGNATURE
#define OFFSET_SIG_HORST_SIGNATURE \
  OFFSET_SIG_SUBTREE_AUTHPATH + SIZEOF_SIG_SUBTREE_AUTHPATH
#define OFFSET_SIG_WOTS_SIGNATURES_AND_AUTHPATHS \
  OFFSET_SIG_HORST_SIGNATURE + SIZEOF_SIG_HORST_SIGNATURE
#define OFFSET_SIG_MESSAGE \
  OFFSET_SIG_WOTS_SIGNATURES_AND_AUTHPATHS + SIZEOF_SIG_WOTS_SIGNATURES_AND_AUTHPATHS

#define CRYPTO_BYTES (SIZEOF_SIG_LEAFIDX +                                  \
                      SIZEOF_SIG_SUBTREE_LEAFIDX +                          \
                      SIZEOF_SIG_MESSAGE_HASH_SEED +                        \
                      SIZEOF_SIG_WOTS_MESSAGE_SIGNATURE +                   \
                      SIZEOF_SIG_SUBTREE_AUTHPATH +                         \
                      SIZEOF_SIG_HORST_SIGNATURE +                          \
                      SIZEOF_SIG_WOTS_SIGNATURES_AND_AUTHPATHS)

#define CRYPTO_DETERMINISTIC 1

/*
 * The short-time state consists of:
 *  - the seed from which the STS elements are generated
 *  - the index of the next WOTS key pair to be used
 *  - the index of the HORST key pair that signs the subtree nodes
 *  - the WOTS public keys, to speed up auth path generation
 *  - the HORST signature of the subtree nodes
 *  - one WOTS signature for each level of the hypertree
 *  - the authentication path throughout the entire hypertree, except for the
 *    lowest subtree
 */
#define CRYPTO_STS_BYTES    (SEED_BYTES + sizeof(TSUBTREE_IDX) +        \
                             (TOTALTREE_HEIGHT + 7) / 8 +               \
                             (1<<SUBTREE_HEIGHT) * HASH_BYTES +         \
                             STS_HORST_SIGBYTES +                       \
                             (N_LEVELS - 1) * WOTS_SIGBYTES +           \
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
int crypto_sts_init(unsigned char *sts, const unsigned char *sk, long long subtree_idx);

int crypto_sts_sign(unsigned char *sig, unsigned long long *slen,
                    const unsigned char *m, unsigned long long mlen,
                    unsigned char *sts,
                    const unsigned char *sk);

long long crypto_sts_remaining_uses(unsigned char *sts);

#endif
