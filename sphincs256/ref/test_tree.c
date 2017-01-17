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

  unsigned char address[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  unsigned char root[HASH_BYTES];
  unsigned char authpath[SUBTREE_HEIGHT*HASH_BYTES];

  // Compute the leaf on which the auth path is based
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_node = 0;

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

int test02()
{
  // Generate keypair
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char* public_seed = sk + SEED_BYTES;

  unsigned char address[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  int layers = 4;
  unsigned char signature_single[layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES)];
  unsigned long long siglen_single = 0;

  unsigned char leaf_single[HASH_BYTES];
  randombytes(leaf_single, HASH_BYTES);

  sign_leaf(leaf_single, 0, layers,
            signature_single, &siglen_single,
            sk, address);

  unsigned char leaf_split[HASH_BYTES];
  randombytes(leaf_split, HASH_BYTES);

  // reset address
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  unsigned char signature_split[layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES)];
  unsigned long long siglen_split = 0;

  sign_leaf(leaf_split, 0, layers - 2,
            signature_split, &siglen_split,
            sk, address);

  // The rest of the signature should start where the previous ended.
  unsigned char* second_half = signature_split + siglen_split;
  sign_leaf(leaf_split, layers - 2, layers,
            second_half, &siglen_split,
            sk, address);

  if(siglen_split != siglen_single) {
    return -1;
  } else if(compare(leaf_single, leaf_split, HASH_BYTES)) {
    return -2;
  } else if(compare(signature_single, signature_split, siglen_single)) {
    hexdump_s(signature_single, 0, siglen_single);
    hexdump_s(signature_split, 0, siglen_split);
    return -3;
  }
  return 0;
}

int test03()
{
  // Generate keypair
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);

  unsigned char* public_seed = sk + SEED_BYTES;

  unsigned char address[ADDR_BYTES];
  int i;
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  int layers = 4;
  unsigned char signature[layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES)];
  unsigned long long siglen = 0;

  unsigned char leaf[HASH_BYTES];
  randombytes(leaf, HASH_BYTES);
  unsigned char root[HASH_BYTES];
  memcpy(root, leaf, HASH_BYTES);

  sign_leaf(root, 0, layers,
            signature, &siglen,
            sk, address);

  // reset address
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  verify_leaf(leaf, 0, layers,
              signature, siglen,
              pk, address);

  return compare(root, leaf, HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test authentication path");
  err |= run_test(&test02, "Test signing parts of the tree structure");
  err |= run_test(&test03, "Test signing and verifying parts of the tree structure");

  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}
