#include <stdio.h>
#include "api.h"
#include "randombytes.h"
#include "wots.h"
#include "testutils.h"
#include "sign.c"

int test01()
{
  // Generate keypair
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char* public_seed = sk + SEED_BYTES;

  uint32_t address[ADDR_SIZE];
  int i;
  for(i = 0; i < ADDR_SIZE; i++) {
    address[i] = 0;
  }

  unsigned char root[HASH_BYTES];
  unsigned char authpath[SUBTREE_HEIGHT*HASH_BYTES];

  // Compute the leaf on which the auth path is based
  set_sphincs_subtree_node(address, 0);

  unsigned char seed[SEED_BYTES];
  get_seed(seed, sk, address);

  unsigned char wots_pk[WOTS_L*HASH_BYTES];
  wots_pkgen(wots_pk,
             seed,
             public_seed,
             address);

  unsigned char leaf[HASH_BYTES];
  l_tree(leaf, wots_pk, address, public_seed);

  // Generate the auth path
  compute_authpath_wots(root,
                        authpath,
                        address,
                        sk,
                        SUBTREE_HEIGHT,
                        public_seed);

  // Verify auth path
  unsigned char generated_root[HASH_BYTES];
  validate_authpath(generated_root,
                    leaf,
                    address,
                    public_seed,
                    authpath,
                    SUBTREE_HEIGHT);

  return compare(root, generated_root, HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test authentication path");

  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}
