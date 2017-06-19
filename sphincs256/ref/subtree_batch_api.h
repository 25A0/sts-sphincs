#include "params.h"
#include <stdint.h>

// Short-time state subtree height
#define STS_SUBTREE_HEIGHT 5
// When changing the subtree height, make sure that the type used for the
// subtree height index is still large enough to capture all indices.
// That is, ensure that STS_SUBTREE_HEIGHT > sizeof(TSUBTREE_IDX) * 8
typedef uint8_t TSUBTREE_IDX;

// To sign 64 Bytes with WOTS_LOGW = 4, L1 is (64 * 8)/4 = 128.
// Accordingly, l2 is ceil(ceil(log_2(128 * (16 - 1)))/4) = 3
#define STS_WOTS_L     131
#define STS_WOTS_L1    128
#define STS_WOTS_LOG_L   7
#define STS_WOTS_SIGBYTES (STS_WOTS_L * HASH_BYTES)

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + \
                               SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      HORST_SIGBYTES +                                  \
                      STS_WOTS_SIGBYTES +                               \
                      (N_LEVELS)*WOTS_SIGBYTES +                        \
                      (TOTALTREE_HEIGHT + STS_SUBTREE_HEIGHT)*HASH_BYTES)
#define CRYPTO_DETERMINISTIC 1

#define CRYPTO_CONTEXTBYTES (SEED_BYTES + sizeof(TSUBTREE_IDX) +        \
                             (TOTALTREE_HEIGHT+7)/8 +                   \
                             HORST_SIGBYTES +                           \
                             N_LEVELS * WOTS_SIGBYTES +                 \
                             TOTALTREE_HEIGHT * HASH_BYTES)
