#ifndef TREE
#define TREE

#include "params.h"
#include "wots.h"
#include "hash_address.h"


void get_seed(unsigned char seed[SEED_BYTES],
              const unsigned char *sk,
              unsigned char *address);

void l_tree(unsigned char *leaf,
            unsigned char *wots_pk,
            unsigned char *address,
            const unsigned char *public_seed);

void l_tree_conf(unsigned char *leaf,
                 unsigned char *wots_pk,
                 unsigned char *address,
                 const unsigned char *public_seed,
                 struct wots_config config);

void gen_leaf_wots(unsigned char leaf[HASH_BYTES],
                   const unsigned char *sk,
                   unsigned char *address,
                   const unsigned char *public_seed);

void gen_leaf_wots_conf(unsigned char leaf[HASH_BYTES],
                        const unsigned char *sk,
                        unsigned char *address,
                        const unsigned char *public_seed,
                        struct wots_config config);

void sts_tree_hash_conf(unsigned char* node,
                        unsigned char* wots_pks,
                        int height,
                        const unsigned char *sk,
                        unsigned char *subtree_address,
                        const unsigned char *public_seed,
                        struct wots_config config);

void treehash(unsigned char *node,
              int height,
              const unsigned char *sk,
              unsigned char *address,
              const unsigned char *public_seed);

void treehash_conf(unsigned char *node,
                   int height,
                   const unsigned char *sk,
                   unsigned char *subtree_address,
                   const unsigned char *public_seed,
                   struct wots_config config);

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

void compute_authpath_wots_conf(unsigned char root[HASH_BYTES],
                                unsigned char *authpath,
                                unsigned char *address,
                                const unsigned char *sk,
                                unsigned int height,
                                const unsigned char *public_seed,
                                struct wots_config config);

void compute_authpath(unsigned char root[HASH_BYTES],
                      unsigned char *authpath,
                      unsigned char *address,
                      const unsigned char* leaves,
                      const unsigned char *sk,
                      unsigned int height,
                      const unsigned char *public_seed);

/* Signs the first HASH_BYTES bytes of leaf with the given secret key sk.
 * num_levels determines how many layers will be signed. The start and end
 * height are set in the addresses.
 */
int sign_leaf(unsigned char* leaf, int num_levels,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *sk,
              unsigned char *leaf_address);

int verify_leaf(unsigned char *root, int num_levels,
                const unsigned char *sigp, unsigned long long smlen,
                const unsigned char *pk,
                unsigned char *leaf_address);
#endif
