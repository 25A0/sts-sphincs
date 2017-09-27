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

void parent(uint32_t tree_height, struct hash_addr addr) {
  *addr.subtree_node = *addr.subtree_address & ((1 << tree_height) - 1);
  *addr.subtree_address = *addr.subtree_address >> tree_height;
  *addr.subtree_layer += 1;
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

