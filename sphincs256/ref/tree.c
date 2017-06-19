#include "tree.h"
#include "hash.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static inline const unsigned char* get_public_seed_from_pk(const unsigned char* pk) {
  return pk + HASH_BYTES;
}

static inline const unsigned char* get_public_seed_from_sk(const unsigned char* sk) {
  return sk + SEED_BYTES;
}

void get_seed(unsigned char seed[SEED_BYTES],
              const unsigned char *sk,
              unsigned char *address)
{
#if (N_LEVELS > 15) && (N_LEVELS < 8)
#error "Need to have 8 <= N_LEVELS <= 15"
#endif

#if TOTALTREE_HEIGHT != 60
#error "Need to have TOTALTREE_HEIGHT == 60"
#endif

  set_type(address, WOTS_ADDR);

  // TODO (moritz): # of used bytes is currently hard-coded to 16 so that only
  // the SPHINCS part of the hash_address is used. I should check if instead we
  // can use the entire address, or at least use a better method to determine
  // how much of the address should be used.
  unsigned int SPHINCS_BYTES = 14;
  unsigned char buffer[SEED_BYTES+SPHINCS_BYTES];
  int i;

  for(i=0;i<SEED_BYTES;i++)
    buffer[i] = sk[i];

  for(i = 0; i < SPHINCS_BYTES; i++) {
    buffer[SEED_BYTES + i] = ((unsigned char*) address)[i];
  }

#if SEED_BYTES != HASH_BYTES
#error "Need to have SEED_BYTES == HASH_BYTES"
#endif
  varlen_hash(seed,buffer,SEED_BYTES+SPHINCS_BYTES);
}


// Hashes two nodes in a binary tree to form its parent node.
// HASH_BYTES bytes will be written to *parent, and
// 2*HASH_BYTES bytes will be read from *nodes.
// *address should point to the address of the parent node
// that is being constructed
static void hash_nodes(unsigned char *parent,
                       const unsigned char *nodes,
                       const unsigned char *address,
                       const unsigned char *public_seed)
{
  hash_2n_n_addr_seeded(parent, nodes, (unsigned char*) address, public_seed);
}

// *address should point to the l_tree that is being constructed.
// the type of the address will be changed to WOTS_L_ADDR.
void l_tree(unsigned char *leaf,
            unsigned char *wots_pk,
            unsigned char *address,
            const unsigned char *public_seed)
{
  l_tree_conf(leaf, wots_pk, address, public_seed, default_wots_config);
}

void l_tree_conf(unsigned char *leaf,
                 unsigned char *wots_pk,
                 unsigned char *address,
                 const unsigned char *public_seed,
                 struct wots_config config)
{
  struct hash_addr addr = init_hash_addr(address);
  set_type(address, WOTS_L_ADDR);
  int l = config.wots_l;
  int i,j = 0;
  for(i=0;i<config.wots_log_l;i++)
  {
    for(j=0 ;j < (l>>1);j++) {
      *addr.wots_l_tree_node = node_index(config.wots_log_l, i+1, j << 1);
      hash_nodes(wots_pk+j*HASH_BYTES,wots_pk+j*2*HASH_BYTES, address, public_seed);
    }

    if(l&1)
    {
      memcpy(wots_pk+(l>>1)*HASH_BYTES,wots_pk+(l-1)*HASH_BYTES, HASH_BYTES);
      l=(l>>1)+1;
    } 
    else 
      l=(l>>1);
  }
  memcpy(leaf,wots_pk,HASH_BYTES);
}


void gen_leaf_wots(unsigned char leaf[HASH_BYTES],
                   const unsigned char *sk,
                   unsigned char *addr,
                   const unsigned char *public_seed)
{
  gen_leaf_wots_conf(leaf, sk, addr, public_seed, default_wots_config);
}

void gen_leaf_wots_conf(unsigned char leaf[HASH_BYTES],
                        const unsigned char *sk,
                        unsigned char *addr,
                        const unsigned char *public_seed,
                        struct wots_config config)
{
  unsigned char seed[SEED_BYTES];
  unsigned char pk[config.wots_l*HASH_BYTES];

  get_seed(seed, sk, addr);
  wots_pkgen_conf(pk, seed, public_seed, addr, config);

  l_tree_conf(leaf, pk, addr, public_seed, config);
}


void treehash(unsigned char *node,
              int height,
              const unsigned char *sk,
              unsigned char *subtree_address,
              const unsigned char *public_seed)
{
  treehash_conf(node, height, sk, subtree_address, public_seed,
                default_wots_config);
}

void treehash_conf(unsigned char *node,
                   int height,
                   const unsigned char *sk,
                   unsigned char *subtree_address,
                   const unsigned char *public_seed,
                   struct wots_config config)
{

  int i, layer;
  unsigned char stack[(height+1)*HASH_BYTES];
  unsigned int  stacklevels[height+1];
  unsigned int  stackoffset=0;
  unsigned char address[ADDR_BYTES];
  memcpy(address, subtree_address, ADDR_BYTES);

  struct hash_addr addr = init_hash_addr(address);
  uint32_t subtree_node = 0;
  uint32_t lastnode = subtree_node + (1<<height);

  for( ; subtree_node < lastnode; subtree_node++)
  {
    *addr.subtree_node = subtree_node;
    gen_leaf_wots_conf(stack+stackoffset*HASH_BYTES, sk, address, public_seed,
                       config);

    stacklevels[stackoffset] = 0;
    stackoffset++;

    while(stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {

      // the layer of the node that we calculate:
      layer = stacklevels[stackoffset-1]+1;
      // the index of the node in that layer is the current subtree_node,
      // shifted to the right by the height of the current layer.
      *addr.subtree_node = node_index(height, layer, subtree_node >> layer);
      set_type(address, SPHINCS_ADDR);

      hash_nodes(stack+(stackoffset-2)*HASH_BYTES,
                 stack+(stackoffset-2)*HASH_BYTES,
                 address,
                 public_seed);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
  }
  for(i=0;i<HASH_BYTES;i++)
    node[i] = stack[i];
}


// address should point to the leaf in the SPHINCS subtree
// that is authenticated by the auth path
void validate_authpath(unsigned char root[HASH_BYTES],
                       const unsigned char leaf[HASH_BYTES],
                       unsigned char *address,
                       const unsigned char *public_seed,
                       const unsigned char *authpath,
                       unsigned int height)
{
  int i,j;
  unsigned char buffer[2*HASH_BYTES];
  struct hash_addr addr = init_hash_addr(address);
  unsigned int leafidx = *addr.subtree_node;
  // Copy of the leaf index so that we can restore it later
  unsigned int idx = leafidx;

  set_type(address, SPHINCS_ADDR);

  if(leafidx&1)
  {
    for(j=0;j<HASH_BYTES;j++)
      buffer[HASH_BYTES+j] = leaf[j];
    for(j=0;j<HASH_BYTES;j++)
      buffer[j] = authpath[j];
  }
  else
  {
    for(j=0;j<HASH_BYTES;j++)
      buffer[j] = leaf[j];
    for(j=0;j<HASH_BYTES;j++)
      buffer[HASH_BYTES+j] = authpath[j];
  }
  authpath += HASH_BYTES;

  for(i=0;i<height-1;i++)
  {
    leafidx >>= 1;
    if(leafidx&1)
    {
      *addr.subtree_node = node_index(height, i+1, leafidx);
      hash_nodes(buffer+HASH_BYTES,buffer,address, public_seed);

      for(j=0;j<HASH_BYTES;j++)
        buffer[j] = authpath[j];
    }
    else
    {
      *addr.subtree_node = node_index(height, i+1, leafidx);
      hash_nodes(buffer,buffer,address, public_seed);

      for(j=0;j<HASH_BYTES;j++)
        buffer[j+HASH_BYTES] = authpath[j];
    }
    authpath += HASH_BYTES;
  }
  *addr.subtree_node = node_index(height, height, 0);
  hash_nodes(root,buffer,address, public_seed);

  // reset leafnode index in address
  *addr.subtree_node = idx;
}

void compute_authpath_wots(unsigned char root[HASH_BYTES],
                           unsigned char *authpath,
                           unsigned char *address,
                           const unsigned char *sk,
                           unsigned int height,
                           const unsigned char *public_seed)
{
  compute_authpath_wots_conf(root, authpath, address, sk, height, public_seed,
                             default_wots_config);
}

void compute_authpath_wots_conf(unsigned char root[HASH_BYTES],
                                unsigned char *authpath,
                                unsigned char *address,
                                const unsigned char *sk,
                                unsigned int height,
                                const unsigned char *public_seed,
                                struct wots_config config)
{
  int i, idx, j;
  struct hash_addr addr = init_hash_addr(address);
  // The index of the node that will be authenticated with the auth path
  int node = *addr.subtree_node;

  unsigned char tree[2*(1<<SUBTREE_HEIGHT)*HASH_BYTES];
  unsigned char seed[(1<<SUBTREE_HEIGHT)*SEED_BYTES];
  unsigned char pk[(1<<SUBTREE_HEIGHT)*config.wots_l*HASH_BYTES];

  // level 0
  for(i = 0; i < (1<<SUBTREE_HEIGHT); i++) {
    *addr.subtree_node = i;
    get_seed(seed + i * SEED_BYTES, sk, address);
  }

  for(i = 0; i < (1<<SUBTREE_HEIGHT); i++) {
    *addr.subtree_node = i;
    wots_pkgen(pk + i * config.wots_l*HASH_BYTES,
               seed + i * SEED_BYTES,
               public_seed,
               address);
  }

  for(i = 0; i < (1<<SUBTREE_HEIGHT); i++) {
    *addr.subtree_node = i;
    l_tree(tree + (1<<SUBTREE_HEIGHT)*HASH_BYTES + i * HASH_BYTES,
           pk  + i * config.wots_l*HASH_BYTES,
           address,
           public_seed);
  }

  int level = 0;

  set_type(address, SPHINCS_ADDR);

  // tree
  for (i = (1<<SUBTREE_HEIGHT); i > 0; i>>=1)
  {
    for (j = 0; j < i; j+=2) {
      *addr.subtree_node = node_index(height, level+1, j >> 1);
      hash_nodes(tree + (i>>1)*HASH_BYTES + (j>>1) * HASH_BYTES,
                 tree + i*HASH_BYTES + j * HASH_BYTES,
                 address,
                 public_seed);
    }

    level++;
  }


  idx = node;

  // copy authpath
  for(i=0;i<height;i++)
    memcpy(authpath + i*HASH_BYTES, tree + ((1<<SUBTREE_HEIGHT)>>i)*HASH_BYTES + ((idx >> i) ^ 1) * HASH_BYTES, HASH_BYTES);

  // copy root
  memcpy(root, tree+HASH_BYTES, HASH_BYTES);

  // reset sphincs node address
  *addr.subtree_node = idx;
}

/* Construct a signature for the given leaf, starting on the layer that is set
 * in the passed address, and ending num_levels higher. The signature is stored
 * in sm, the total length is stored in smlen. The secret key sk is used to
 * sign the leaf.  The given address defines the position of the leaf.  When
 * this function returns, leaf will contain the hash of the tree, and address
 * will point to the root of the tree
 */
int sign_leaf(unsigned char* leaf, int num_levels,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *sk,
              unsigned char *address)
{
  unsigned char root[HASH_BYTES];
  memcpy(root, leaf, HASH_BYTES);
  unsigned char seed[SEED_BYTES];
  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  struct hash_addr addr = init_hash_addr(address);
  int last_level = *addr.subtree_layer + num_levels;
  for(; *addr.subtree_layer < last_level;)
  {
    get_seed(seed, sk, address); //XXX: Don't use the same address as for horst_sign here!
    wots_sign(sm, root, seed, public_seed, address);
    sm += WOTS_SIGBYTES;
    *smlen += WOTS_SIGBYTES;

    compute_authpath_wots(root,sm,address,sk,SUBTREE_HEIGHT, public_seed);
    sm += SUBTREE_HEIGHT*HASH_BYTES;
    *smlen += SUBTREE_HEIGHT*HASH_BYTES;

    parent(SUBTREE_HEIGHT, addr);
  }
  memcpy(leaf, root, HASH_BYTES);
  return 0;
}

/* Reconstructs the tree hash from the given signature.  The signature should
 * be stored in sign. smlen should initially contain the number of bytes that
 * can be read from sign. When the function returns, smlen will contain the
 * remaining bytes that were not consumed by this function. address initially
 * defines the position of the leaf, and contains the position of the generated
 * tree root when the function returns. num_levels defines for how many layers
 * the signature is verified, starting from the layer that is defined in address.
 *
 * The return value only indicates whether there were any errors -- compare the
 * content of leaf with the expected treehash once this functino returns to
 * verify the signature.
 */
int verify_leaf(unsigned char *leaf, int num_levels,
                unsigned char *sigp, unsigned long long smlen,
                const unsigned char *pk,
                unsigned char *address)
{
  unsigned char wots_pk[WOTS_L*HASH_BYTES];
  unsigned char pkhash[HASH_BYTES];
  const unsigned char* public_seed = get_public_seed_from_pk(pk);
  struct hash_addr addr = init_hash_addr(address);
  int last_level = *addr.subtree_layer + num_levels;
  for(; *addr.subtree_layer < last_level;)
  {
    wots_verify(wots_pk, sigp, leaf, public_seed, address);

    sigp += WOTS_SIGBYTES;
    smlen -= WOTS_SIGBYTES;

    l_tree(pkhash, wots_pk, address, public_seed);
    // validate_authpath(root, pkhash, leafidx & 0x1f, sigp, tpk, SUBTREE_HEIGHT);
    validate_authpath(leaf, pkhash, address, public_seed, sigp, SUBTREE_HEIGHT);

    parent(SUBTREE_HEIGHT, addr);

    sigp += SUBTREE_HEIGHT*HASH_BYTES;
    smlen -= SUBTREE_HEIGHT*HASH_BYTES;
  }
  return 0;
}
