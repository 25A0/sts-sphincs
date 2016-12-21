/*
hash_address.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef HASH_ADDRESS
#define HASH_ADDRESS

#include <stdint.h>

#define ADDR_BYTES 24

// To avoid that hash calls in different data structure use the
// same address by mistake, the address type uniquely identifies
// the data structure in which the hash is used.
enum addr_type {
  SPHINCS_ADDR, // hash is used to construct or address subtree node
  WOTS_ADDR, // hash is used in WOTS key gen, signing or verification
  WOTS_L_ADDR, // hash is used in construction of WOTS L-tree
  HORST_ADDR, // hash is used in HORST key gen, signing, verification,
              // or construction on top of HORST pk

  NUM_TYPES // helper value to find out how many types there are
};

struct hash_addr{
  // The struct does not contain the address type.
  // Whenever the address type changes, the type-specific
  // fields need to be reset. To enforce this, the type
  // needs to be changed with the set_type function.

  uint8_t *subtree_layer;
  uint64_t *subtree_address;
  uint32_t *subtree_node;

  // For type WOTS_ADDR:
  uint8_t *wots_ots_index;
  uint8_t *wots_ots_position;

  // For type WOTS_L_ADDR:
  uint32_t *wots_l_tree_node;

  // For type HORST_ADDR:
  uint32_t *horst_node;
};
struct hash_addr init_hash_addr(unsigned char *bytes);

/*
 * Address layout:
 *
 *For all types:
 *  0      |-  8b -| Address type
 *
 *  1      |-  8b -| SPHINCS layer
 *  2 -  9 |- 64b -| SPHINCS subtree address
 *
 * 10 - 13 |- 32b -| Node or leave within SPHINCS subtree
 *
 * For type WOTS_ADDR:
 * 14 - 17 |- WOTS_LOG_L -| WOTS OTS index
 * 18 - 21 |- WOTS_LOG_W -| Position within OTS chain, or 0 for initial key expansion
 *
 * For type WOTS_L_ADDR:
 * 14 - 17 |-32b-| Node within WOTS L-tree
 *
 * For type HORST_ADDR:
 * 14 - 17 |-32b-| Node or leave within HORST tree
 */

/*
 * Calculates the index of a node on a given layer in a binary tree.
 * Layers are counted from bottom to top, with 0 being the layer that
 * holds all leaves, and h-1 being the layer that holds a single node.
 * Nodes in each layer are counted from left to right, starting with 0.
 */
uint32_t node_index(uint32_t tree_height, uint32_t layer, uint32_t node);

/*
 * Sets the type of address, and clears the type-specific address field(s).
 */
void set_type(unsigned char addr[ADDR_BYTES], enum addr_type type);

// SPHINCS

void set_sphincs_subtree_layer(unsigned char addr[ADDR_BYTES], uint32_t level);
uint32_t get_sphincs_subtree_layer(unsigned char addr[ADDR_BYTES]);

void set_sphincs_subtree(unsigned char addr[ADDR_BYTES], uint64_t tree);
uint64_t get_sphincs_subtree(unsigned char addr[ADDR_BYTES]);

void set_sphincs_subtree_node(unsigned char addr[ADDR_BYTES], uint32_t node);
uint32_t get_sphincs_subtree_node(unsigned char addr[ADDR_BYTES]);

// WOTS OTS

void set_wots_ots_index(unsigned char addr[ADDR_BYTES], uint32_t ots);

void set_wots_chain_index(unsigned char addr[ADDR_BYTES], uint32_t chain);

// WOTS L-tree

void set_wots_l_node(unsigned char addr[ADDR_BYTES], uint32_t node);

// HORST

void set_horst_node(unsigned char addr[ADDR_BYTES], uint32_t node);

#endif
