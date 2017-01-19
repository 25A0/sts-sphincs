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

  int layers = 4;

  unsigned char address[ADDR_BYTES];
  zerobytes(address, ADDR_BYTES);
  struct hash_addr addr = init_hash_addr(address);
  // Configure the adress to non-zero values
  *addr.subtree_address = randomint(0, 1 << 4);
  *addr.subtree_node = randomint(0, 1 << SUBTREE_HEIGHT);

  // create a copy of that address
  unsigned char address_split[ADDR_BYTES];
  memcpy(address_split, address, ADDR_BYTES);

  unsigned char signature_single[layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES)];
  zerobytes(signature_single, layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES));
  unsigned long long siglen_single = 0;

  unsigned char leaf_single[HASH_BYTES];
  randombytes(leaf_single, HASH_BYTES);
  unsigned char leaf_split[HASH_BYTES];
  memcpy(leaf_split, leaf_single, HASH_BYTES);

  sign_leaf(leaf_single, layers,
            signature_single, &siglen_single,
            sk, address);

  unsigned char signature_split[layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES)];
  zerobytes(signature_split, layers * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES));
  unsigned long long siglen_split = 0;

  sign_leaf(leaf_split, 2,
            signature_split, &siglen_split,
            sk, address_split);

  // The rest of the signature should start where the previous ended.
  unsigned char* second_half = signature_split + siglen_split;
  sign_leaf(leaf_split, 2,
            second_half, &siglen_split,
            sk, address_split);

  int err = 0;
  err |= (siglen_split != siglen_single);
  err |= compare(leaf_single, leaf_split, HASH_BYTES);
  err |= compare(address, address_split, ADDR_BYTES);
  err |= compare(signature_single, signature_split, siglen_single);

  return err;
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

  sign_leaf(root, layers,
            signature, &siglen,
            sk, address);

  // reset address
  for(i = 0; i < ADDR_BYTES; i++) {
    address[i] = 0;
  }

  verify_leaf(leaf, layers,
              signature, siglen,
              pk, address);

  return compare(root, leaf, HASH_BYTES);
}

int main(int argc, char const *argv[])
{
  int err = 0;

  err |= run_test(&test01, "Test authentication path");
  err |= run_test(&test02, "Testing that splitting up the signature makes no difference");
  err |= run_test(&test03, "Testing that a partial signature can be verified");

  if(err)
  {
    printf("Expected and actual results differed.\n");
  }
  return err;
}
