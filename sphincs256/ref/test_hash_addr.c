#include <stdio.h>
#include "prg.h"
#include "params.h"
#include "hash_address.h"
#include "testutils.h"

int test01() {
  uint32_t address[ADDR_SIZE];
  int layer = 8;
  set_sphincs_subtree_layer(address, layer);
  int ret_layer = get_sphincs_subtree_layer(address);
  if(layer != ret_layer) return 1;
  return 0;
}

int test02() {
  uint32_t address[ADDR_SIZE];
  int layer = 8;
  set_sphincs_subtree_layer(address, layer);
  int tree = 12345;
  set_sphincs_subtree(address, tree);
  int ret_layer = get_sphincs_subtree_layer(address);
  int ret_tree = get_sphincs_subtree(address);
  if(layer != ret_layer) return 1;
  if(tree != ret_tree) return 1;
  return 0;
}

int test03() {
  uint32_t address[ADDR_SIZE];
  int layer = 8;
  set_sphincs_subtree_layer(address, layer);
  int ret_layer = get_sphincs_subtree_layer(address);
  if(layer != ret_layer) return 1;
  return 0;
}

int main(int argc, char const *argv[])
{
  int err = 0;
  
  err |= test01();
  err |= test02();
  err |= test03();
  
  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}

