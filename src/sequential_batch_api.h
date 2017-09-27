#include "params.h"

#define CRYPTO_SECRETKEYBYTES (SEED_BYTES + PUBLIC_SEED_BYTES + SK_RAND_SEED_BYTES)
#define CRYPTO_PUBLICKEYBYTES (HASH_BYTES + PUBLIC_SEED_BYTES)
#define CRYPTO_BYTES (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT+7)/8 + \
                      HORST_SIGBYTES +                                  \
                      (TOTALTREE_HEIGHT/SUBTREE_HEIGHT)*WOTS_SIGBYTES + \
                      TOTALTREE_HEIGHT*HASH_BYTES)
#define CRYPTO_DETERMINISTIC 1

#define CRYPTO_CONTEXTBYTES ((TOTALTREE_HEIGHT+7)/8 +          \
                             (1 << SUBTREE_HEIGHT) * HASH_BYTES +       \
                             (N_LEVELS - 1) * (WOTS_SIGBYTES + \
                                               SUBTREE_HEIGHT * HASH_BYTES))