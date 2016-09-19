/*
hash_address.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#include "hash_address.h"

uint32_t node_index(uint32_t tree_height, uint32_t layer, uint32_t node)
{
  if(layer == 0) return node;
  return (1<<tree_height + 1) - 1 // All nodes in the entire tree
    - ((1<<(tree_height + 1 - layer)) - 1) // Subtract nodes of a tree that is
                                       // `layer` layers smaller to get offset
    + node; // Add the index of the node in that layer
}

void set_type(uint32_t addr[ADDR_SIZE], enum addr_type type)
{
  addr[0] = (uint32_t) type;
  int i;
  for(i = 4; i < ADDR_SIZE; i++){
    addr[i] = 0;
  }
}

// SPHINCS

void set_sphincs_subtree(uint32_t addr[ADDR_SIZE], uint64_t tree)
{
  addr[1] = (uint32_t) (tree >> 32);
  addr[2] = (uint32_t) tree;
}

void set_sphincs_subtree_node(uint32_t addr[ADDR_SIZE], uint32_t node)
{
  addr[3] = node;
}

// WOTS OTS

void set_wots_ots_index(uint32_t addr[ADDR_SIZE], uint32_t ots)
{
  addr[4] = ots;
}

void set_wots_chain_index(uint32_t addr[ADDR_SIZE], uint32_t chain)
{
  addr[5] = chain;
}

// WOTS L-tree

void set_wots_l_node(uint32_t addr[ADDR_SIZE], uint32_t node)
{
  addr[4] = node;
}

// HORST

void set_horst_node(uint32_t addr[ADDR_SIZE], uint32_t node)
{
  addr[4] = node;
}