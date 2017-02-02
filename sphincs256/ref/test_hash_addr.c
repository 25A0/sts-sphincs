#include <stdio.h>
#include "prg.h"
#include "params.h"
#include "hash_address.h"
#include "testutils.h"

int test01() {
  unsigned char address[ADDR_BYTES];
  int layer = 8;
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = layer;
  int ret_layer = *addr.subtree_layer;
  if(layer != ret_layer) return 1;
  return 0;
}

int test02() {
  unsigned char address[ADDR_BYTES];
  int layer = 8;
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = layer;
  int tree = 12345;
  *addr.subtree_address = tree;
  int ret_layer = *addr.subtree_layer;
  int ret_tree = *addr.subtree_address;
  if(layer != ret_layer) return 1;
  if(tree != ret_tree) return 1;
  return 0;
}

int test03() {
  unsigned char address[ADDR_BYTES];
  struct hash_addr addr = init_hash_addr(address);
  int layer = 8;
  *addr.subtree_layer = layer;
  int ret_layer = *addr.subtree_layer;
  if(layer != ret_layer) return 1;
  return 0;
}

int test04() {
  unsigned char address[ADDR_BYTES];
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = 1;
  *addr.subtree_address = 11;
  *addr.subtree_node = 7;
  int height = 3;
  parent(height, addr);

  int res = 0;
  res |= !(*addr.subtree_layer == 2);
  res |= !(*addr.subtree_address == 1);
  res |= !(*addr.subtree_node == 3);

  return 0;
}

int main(int argc, char const *argv[])
{
  int err = 0;
  
  err |= test01();
  err |= test02();
  err |= test03();
  err |= test04();
  
  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}

