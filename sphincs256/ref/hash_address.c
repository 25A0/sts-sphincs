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
  return (1<<(tree_height + 1)) - 1 // All nodes in the entire tree
    - ((1<<(tree_height + 1 - layer)) - 1) // Subtract nodes of a tree that is
                                       // `layer` layers smaller to get offset
    + node; // Add the index of the node in that layer
}

void set_type(unsigned char addr[ADDR_BYTES], enum addr_type type)
{
  addr[0] = (unsigned char) type;
  int i;
  for(i = 14; i < ADDR_BYTES; i++){
    addr[i] = 0;
  }
}

struct hash_addr init_hash_addr(unsigned char *bytes)
{
  struct hash_addr addr;
  // For all types
  addr.subtree_layer = (uint8_t *) (bytes + 1);
  addr.subtree_address = (uint64_t *) (bytes + 2);
  addr.subtree_node = (uint32_t *) (bytes + 10);

  // For type WOTS_ADDR:
  addr.wots_ots_index = (uint8_t *) (bytes + 14);
  addr.wots_ots_position = (uint8_t *) (bytes + 18);

  // For type WOTS_L_ADDR:
  addr.wots_l_tree_node = (uint32_t *) (bytes + 14);

  // For type HORST_ADDR:
  addr.horst_node = (uint32_t *) (bytes + 14);

  return addr;
}

// SPHINCS

void set_sphincs_subtree_layer(unsigned char addr[ADDR_BYTES], uint32_t level)
{
  addr[1] = (unsigned char) level;
}

uint32_t get_sphincs_subtree_layer(unsigned char addr[ADDR_BYTES])
{
  return addr[1];
}

void set_sphincs_subtree(unsigned char addr[ADDR_BYTES], uint64_t tree)
{
  *((uint64_t *) (addr + 2)) = tree;
}

uint64_t get_sphincs_subtree(unsigned char addr[ADDR_BYTES])
{
  return *((uint64_t *) (addr + 2));
}

void set_sphincs_subtree_node(unsigned char addr[ADDR_BYTES], uint32_t node)
{
  *((uint32_t *) (addr + 10)) = node;
}

uint32_t get_sphincs_subtree_node(unsigned char addr[ADDR_BYTES])
{
  return *((uint32_t *) (addr + 10));
}

// WOTS OTS

void set_wots_ots_index(unsigned char addr[ADDR_BYTES], uint32_t ots)
{
  *((uint32_t *) (addr + 14)) = ots;
}

void set_wots_chain_index(unsigned char addr[ADDR_BYTES], uint32_t chain)
{
  *((uint32_t *) (addr + 18)) = chain;
}

// WOTS L-tree

void set_wots_l_node(unsigned char addr[ADDR_BYTES], uint32_t node)
{
  *((uint32_t *) (addr + 14)) = node;
}

// HORST

void set_horst_node(unsigned char addr[ADDR_BYTES], uint32_t node)
{
  *((uint32_t *) (addr + 14)) = node;
}
