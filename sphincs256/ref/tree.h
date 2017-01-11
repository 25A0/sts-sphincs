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

#endif
