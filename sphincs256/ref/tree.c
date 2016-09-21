#include "tree.h"
#include <stdlib.h>
#include <string.h>

void get_seed(unsigned char seed[SEED_BYTES],
              const unsigned char *sk,
              const leafaddr *a)
{
#if (N_LEVELS > 15) && (N_LEVELS < 8)
#error "Need to have 8 <= N_LEVELS <= 15"
#endif

#if SUBTREE_HEIGHT != 5
#error "Need to have SUBTREE_HEIGHT == 5"
#endif

#if TOTALTREE_HEIGHT != 60
#error "Need to have TOTALTREE_HEIGHT == 60"
#endif
  unsigned char buffer[SEED_BYTES+8];
  unsigned long long t;
  int i;

  for(i=0;i<SEED_BYTES;i++)
    buffer[i] = sk[i];

  //4 bits to encode level
  t  = a->level;
  //55 bits to encode subtree
  t |= a->subtree << 4;
  //5 bits to encode leaf
  t |= (unsigned long long)a->subleaf << 59;

  for(i=0;i<8;i++)
    buffer[SEED_BYTES+i] = (t >> 8*i) & 0xff;
  
#if SEED_BYTES != HASH_BYTES
#error "Need to have SEED_BYTES == HASH_BYTES"
#endif
  varlen_hash(seed,buffer,SEED_BYTES+8);
}


// Hashes two nodes in a binary tree to form its parent node.
// HASH_BYTES bytes will be written to *parent, and
// 2*HASH_BYTES bytes will be read from *nodes.
static void hash_nodes(unsigned char *parent,
                       const unsigned char *nodes,
                       const unsigned char *masks)
{
  hash_2n_n_mask(parent, nodes, masks);
}

void l_tree(unsigned char *leaf,
            unsigned char *wots_pk,
            const unsigned char *masks)
{
  int l = WOTS_L;
  int i,j = 0;
  for(i=0;i<WOTS_LOG_L;i++)
  {
    for(j=0 ;j < (l>>1);j++)
      hash_nodes(wots_pk+j*HASH_BYTES,wots_pk+j*2*HASH_BYTES, masks+i*2*HASH_BYTES);

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
                   const unsigned char *masks,
                   const unsigned char *sk,
                   const leafaddr *a)
{
  unsigned char seed[SEED_BYTES];
  unsigned char pk[WOTS_L*HASH_BYTES];

  unsigned char public_seed[PUBLIC_SEED_BYTES];
  int i;
  for(i = 0; i < PUBLIC_SEED_BYTES; i++) {
    public_seed[i] = 0;
  }

  uint32_t addr[ADDR_SIZE];
  for(i = 0; i < ADDR_SIZE; i++) {
    addr[i] = 0;
  }

  get_seed(seed, sk, a);
  wots_pkgen(pk, seed, public_seed, addr);

  l_tree(leaf, pk, masks);
}


void treehash(unsigned char *node,
              int height,
              const unsigned char *sk,
              const leafaddr *leaf,
              const unsigned char *masks)
{

  leafaddr a = *leaf;
  int lastnode,i;
  unsigned char stack[(height+1)*HASH_BYTES];
  unsigned int  stacklevels[height+1];
  unsigned int  stackoffset=0;
  unsigned int maskoffset =0;

  lastnode = a.subleaf+(1<<height);

  for(;a.subleaf<lastnode;a.subleaf++) 
  {
    gen_leaf_wots(stack+stackoffset*HASH_BYTES,masks,sk,&a);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    while(stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {
      //MASKS
      maskoffset = 2*(stacklevels[stackoffset-1] + WOTS_LOG_L)*HASH_BYTES;
      hash_nodes(stack+(stackoffset-2)*HASH_BYTES,stack+(stackoffset-2)*HASH_BYTES,
          masks+maskoffset);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
  }
  for(i=0;i<HASH_BYTES;i++)
    node[i] = stack[i];
}


void validate_authpath(unsigned char root[HASH_BYTES],
                       const unsigned char leaf[HASH_BYTES],
                       unsigned int leafidx,
                       const unsigned char *authpath,
                       const unsigned char *masks,
                       unsigned int height)
{
  int i,j;
  unsigned char buffer[2*HASH_BYTES];

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
      hash_nodes(buffer+HASH_BYTES,buffer,masks+2*(WOTS_LOG_L+i)*HASH_BYTES);
      for(j=0;j<HASH_BYTES;j++)
        buffer[j] = authpath[j];
    }
    else
    {
      hash_nodes(buffer,buffer,masks+2*(WOTS_LOG_L+i)*HASH_BYTES);
      for(j=0;j<HASH_BYTES;j++)
        buffer[j+HASH_BYTES] = authpath[j];
    }
    authpath += HASH_BYTES;
  }
  hash_nodes(root,buffer,masks+2*(WOTS_LOG_L+height-1)*HASH_BYTES);
}

void compute_authpath_wots(unsigned char root[HASH_BYTES],
                           unsigned char *authpath,
                           const leafaddr *a,
                           const unsigned char *sk,
                           const unsigned char *masks,
                           unsigned int height)
{
  int i, idx, j;
  leafaddr ta = *a;

  unsigned char tree[2*(1<<SUBTREE_HEIGHT)*HASH_BYTES];
  unsigned char seed[(1<<SUBTREE_HEIGHT)*SEED_BYTES];
  unsigned char pk[(1<<SUBTREE_HEIGHT)*WOTS_L*HASH_BYTES];

  unsigned char public_seed[PUBLIC_SEED_BYTES];

  for(i = 0; i < PUBLIC_SEED_BYTES; i++) {
    public_seed[i] = 0;
  }

  uint32_t addr[ADDR_SIZE];
  for(i = 0; i < ADDR_SIZE; i++) {
    addr[i] = 0;
  }


  // level 0
  for(ta.subleaf = 0; ta.subleaf < (1<<SUBTREE_HEIGHT); ta.subleaf++)
    get_seed(seed + ta.subleaf * SEED_BYTES, sk, &ta);

  for(ta.subleaf = 0; ta.subleaf < (1<<SUBTREE_HEIGHT); ta.subleaf++)
    wots_pkgen(pk + ta.subleaf * WOTS_L*HASH_BYTES,
               seed + ta.subleaf * SEED_BYTES,
               public_seed,
               addr);

  for(ta.subleaf = 0; ta.subleaf < (1<<SUBTREE_HEIGHT); ta.subleaf++)
    l_tree(tree + (1<<SUBTREE_HEIGHT)*HASH_BYTES + ta.subleaf * HASH_BYTES,
        pk  + ta.subleaf * WOTS_L*HASH_BYTES, masks);

  int level = 0;

  // tree
  for (i = (1<<SUBTREE_HEIGHT); i > 0; i>>=1)
  {
    for (j = 0; j < i; j+=2)
      hash_nodes(tree + (i>>1)*HASH_BYTES + (j>>1) * HASH_BYTES, 
          tree + i*HASH_BYTES + j * HASH_BYTES,
          masks+2*(WOTS_LOG_L + level)*HASH_BYTES);

    level++;
  }


  idx = a->subleaf;

  // copy authpath
  for(i=0;i<height;i++)
    memcpy(authpath + i*HASH_BYTES, tree + ((1<<SUBTREE_HEIGHT)>>i)*HASH_BYTES + ((idx >> i) ^ 1) * HASH_BYTES, HASH_BYTES);

  // copy root
  memcpy(root, tree+HASH_BYTES, HASH_BYTES);
}


