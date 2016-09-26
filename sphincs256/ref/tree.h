#ifndef TREE
#define TREE

#include "params.h"
#include "hash_address.h"


typedef struct{
  int level;
  unsigned long long subtree;
  int subleaf;
} leafaddr;

void get_seed(unsigned char seed[SEED_BYTES],
              const unsigned char *sk,
              const leafaddr *a);

void l_tree(unsigned char *leaf,
            unsigned char *wots_pk,
            const unsigned char *masks);

void gen_leaf_wots(unsigned char leaf[HASH_BYTES],
                   const unsigned char *masks,
                   const unsigned char *sk,
                   const leafaddr *a,
                   const unsigned char *public_seed);

void treehash(unsigned char *node,
              int height,
              const unsigned char *sk,
              const leafaddr *leaf,
              const unsigned char *masks,
              const unsigned char *public_seed);

void validate_authpath(unsigned char root[HASH_BYTES],
                       const unsigned char leaf[HASH_BYTES],
                       unsigned int leafidx,
                       const unsigned char *authpath,
                       const unsigned char *masks,
                       unsigned int height);

void compute_authpath_wots(unsigned char root[HASH_BYTES],
                           unsigned char *authpath,
                           const leafaddr *a,
                           const unsigned char *sk,
                           const unsigned char *masks,
                           unsigned int height,
                           const unsigned char *public_seed);
#endif
