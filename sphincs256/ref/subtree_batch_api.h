#include "params.h"
#include <stdint.h>

// Short-time state subtree height
#define STS_SUBTREE_HEIGHT 5
// When changing the subtree height, make sure that the type used for the
// subtree height index is still large enough to capture all indices.
// That is, ensure that STS_SUBTREE_HEIGHT > sizeof(TSUBTREE_IDX) * 8
typedef uint8_t TSUBTREE_IDX;

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + \
                               SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      HORST_SIGBYTES +                                  \
                      (N_LEVELS + 1)*WOTS_SIGBYTES +                    \
                      (TOTALTREE_HEIGHT + STS_SUBTREE_HEIGHT)*HASH_BYTES)
#define CRYPTO_DETERMINISTIC 1

#define CRYPTO_CONTEXTBYTES (SEED_BYTES + sizeof(TSUBTREE_IDX) +        \
                             (TOTALTREE_HEIGHT+7)/8 +                   \
                             HORST_SIGBYTES +                           \
                             N_LEVELS * WOTS_SIGBYTES +                 \
                             TOTALTREE_HEIGHT * HASH_BYTES)
