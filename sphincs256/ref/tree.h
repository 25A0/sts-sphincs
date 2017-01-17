#ifndef TREE
#define TREE

#include "params.h"
#include "hash_address.h"


void get_seed(unsigned char seed[SEED_BYTES],
              const unsigned char *sk,
              unsigned char *address);

void l_tree(unsigned char *leaf,
            unsigned char *wots_pk,
            unsigned char *address,
            const unsigned char *public_seed);

void gen_leaf_wots(unsigned char leaf[HASH_BYTES],
                   const unsigned char *sk,
                   unsigned char *address,
                   const unsigned char *public_seed);

void treehash(unsigned char *node,
              int height,
              const unsigned char *sk,
              unsigned char *address,
              const unsigned char *public_seed);

void validate_authpath(unsigned char root[HASH_BYTES],
                       const unsigned char leaf[HASH_BYTES],
                       unsigned char *address,
                       const unsigned char *public_seed,
                       const unsigned char *authpath,
                       unsigned int height);

void compute_authpath_wots(unsigned char root[HASH_BYTES],
                           unsigned char *authpath,
                           unsigned char *address,
                           const unsigned char *sk,
                           unsigned int height,
                           const unsigned char *public_seed);

/* Signs the first HASH_BYTES bytes of leaf with the given secret key sk.
 * The start_height and end_height determines how many layers will be signed.
 */
int sign_leaf(unsigned char* leaf, int start_height, int end_height,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *sk,
              unsigned char *leaf_address);

int verify_leaf(unsigned char *root, int start_height, int end_height,
                unsigned char *sigp, unsigned long long smlen,
                const unsigned char *pk,
                unsigned char *root_address);
#endif
