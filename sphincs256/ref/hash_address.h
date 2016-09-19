/*
hash_address.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef HASH_ADDRESS
#define HASH_ADDRESS

#include <stdint.h>

#define ADDR_SIZE 6
#define ADDR_BYTES (ADDR_SIZE*4)

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

/*
 * Address layout:
 *
 *For all types:
 * 0 |- 32b -| Address type
 *
 * 1 |- 64b -
 * 2  -------| SPHINCS subtree address
 *
 * 3 |- 32b -| Node or leave within SPHINCS subtree
 *
 * For type WOTS_ADDR:
 * 4 |- WOTS_LOG_L -| WOTS OTS index
 * 5 |- WOTS_LOG_W -| Position within OTS chain
 *
 * For type WOTS_L_ADDR:
 * 4 |-32b-| Node within WOTS L-tree
 *
 * For type HORST_ADDR:
 * 4 |-32b-| Node or leave within HORST tree
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
void set_type(uint32_t addr[ADDR_SIZE], enum addr_type type);

// SPHINCS

void set_sphincs_subtree(uint32_t addr[ADDR_SIZE], uint64_t tree);

void set_sphincs_subtree_node(uint32_t addr[ADDR_SIZE], uint32_t node);

// WOTS OTS

void set_wots_ots_index(uint32_t addr[ADDR_SIZE], uint32_t ots);

void set_wots_chain_index(uint32_t addr[ADDR_SIZE], uint32_t chain);

// WOTS L-tree

void set_wots_l_node(uint32_t addr[ADDR_SIZE], uint32_t node);

// HORST

void set_horst_node(uint32_t addr[ADDR_SIZE], uint32_t node);

#endif
