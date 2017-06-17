#include "batch_sign.h"
#include "sign.h"
#include "hash.h"
#include "tree.h"
#include "wots.h"
#include "horst.h"
#include "hash_address.h"
#include "randombytes.h"
#include "zerobytes.h"
#include "subtree_batch_api.h"
#include "crypto_hash_blake512.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct batch_context{
  // The seed that produces the secret keys of the WOTS key pairs that form the
  // leaves of the short-time subtree
  unsigned char* subtree_sk_seed;

  // The index of the leaf in the subtree that should be used to sign the next
  // message
  TSUBTREE_IDX* next_subtree_leafidx;

  // The seed that was used to produce the message hash that is signed
  // with HORST
  unsigned char* message_hash_seed;

  // The leaf index that is parent to the short-time subtree
  unsigned long long* leafidx;

  // The HORST signature that signs the root of the short-time subtree
  unsigned char* horst_signature;

  // The N_LEVELS WOTS signatures that sign level_0_hash under the
  // key pair that was used to generate this context
  unsigned char* wots_signatures;

};

const struct batch_context init_batch_context(unsigned char *bytes) {
  struct batch_context context;
  int offset = 0;

  context.subtree_sk_seed = bytes + offset;
  offset += SEED_BYTES;

  context.next_subtree_leafidx = (TSUBTREE_IDX*) (bytes + offset);
  offset += sizeof(TSUBTREE_IDX);

  context.message_hash_seed = bytes + offset;
  offset += MESSAGE_HASH_SEED_BYTES;

  context.leafidx = (unsigned long long*) (bytes + offset);
  offset += (TOTALTREE_HEIGHT+7)/8;

  context.horst_signature = bytes + offset;
  offset += HORST_SIGBYTES;

  context.wots_signatures = bytes + offset;
  offset += N_LEVELS * WOTS_SIGBYTES + TOTALTREE_HEIGHT * HASH_BYTES;

  assert(offset == CRYPTO_CONTEXTBYTES);

  return context;
}

static int increment_context(unsigned char *context_bytes)
{
  struct batch_context context = init_batch_context(context_bytes);

  // Make sure that the next leafidx actually exists in the
  // short-time subtree
  if(*context.next_subtree_leafidx < (1 << STS_SUBTREE_HEIGHT) - 1) {
    // Increment the leafidx that will be used for the next leaf
    (*context.next_subtree_leafidx)++;
    return 0;
  } else {
    return 1;
  }
}

static int
get_entropy(unsigned long long *out, const unsigned char *seed, int lseed)
{
  unsigned char scratch[lseed + SEED_BYTES];
  memcpy(scratch, seed, lseed);
  randombytes(scratch + lseed, SEED_BYTES);
  crypto_hash_blake512((unsigned char*) out, scratch,
                       lseed + SEED_BYTES);
  zerobytes(scratch, lseed + SEED_BYTES);
  return 0;
}

int crypto_context_init(unsigned char *context_buffer, unsigned long long *clen,
                        const unsigned char *sk, long long user_leaf_idx)
{
  struct batch_context context = init_batch_context(context_buffer);

  unsigned long long rnd[8]; // buffer that holds random entropy
  int has_entropy = 0; // whether system entropy was already generated
  int next_unused_entropy = 0; // next index in the entropy buffer that was not
                               // used yet

  // If the user-chosen leaf index is -1, then we choose a random leaf,
  // otherewise we use the one provided by the user
  if(user_leaf_idx == (long long) -1) {
    // ===============================
    // Generate a random leaf idx
    // ===============================

    int err = get_entropy(rnd, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES,
                          SK_RAND_SEED_BYTES);
    if(err) return err;
    has_entropy = 1;

    *context.leafidx = (rnd[next_unused_entropy++] &
                        (((unsigned long long) 1 << TOTALTREE_HEIGHT) - 1));
  } else if(user_leaf_idx < 0) {
    // Other negative leaf indices are considered an error.
    // If someone tried to iterate through all leaves and caused an overflow,
    // this case would catch that, instead of starting to use random leaves.
    return -1;
  } else if(user_leaf_idx >= (long long) 1 << (TOTALTREE_HEIGHT) ) {
    // This index is not a valid subtree index.
    return -2;
  } else {
    *context.leafidx = user_leaf_idx;
  }

  // Generate a secret key to source the leaves of the short-time subtree
  if(!has_entropy) {
    int err = get_entropy(rnd, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES,
                          SK_RAND_SEED_BYTES);
    if(err) return err;
    has_entropy = 1;
  }

  // Make sure that there is enough entropy available to provide a seed
  // from which the short-time subtree can be generated.
  assert(SEED_BYTES <= sizeof(unsigned long long) * (8 - next_unused_entropy));

  // Store that secret key in the context
  assert(SEED_BYTES % sizeof(unsigned long long) == 0);
  memcpy(context.subtree_sk_seed, rnd + next_unused_entropy, SEED_BYTES);
  next_unused_entropy += SEED_BYTES / sizeof(unsigned long long);

  // Initialize the context to use leaf 0 of the short-time subtree
  *context.next_subtree_leafidx = (unsigned long) 0;

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = N_LEVELS + 1;
  *address.subtree_address = *context.leafidx;
  *address.subtree_node = *context.next_subtree_leafidx;

  // Build the root of the short-time subtree
  unsigned char root[HASH_BYTES];
  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  treehash(root,
           STS_SUBTREE_HEIGHT,
           context.subtree_sk_seed,
           addr_bytes,
           public_seed);
  // Create signature for that root at the given leafidx
  // And store that signature in the context
  *address.subtree_layer = N_LEVELS;
  *address.subtree_address = *context.leafidx >> SUBTREE_HEIGHT;
  *address.subtree_node = *context.leafidx % (1<<SUBTREE_HEIGHT);

  unsigned long long horst_sigbytes;
  unsigned char seed[SEED_BYTES];
  get_seed(seed, sk, addr_bytes);

  // The message hash seed depends on the seed in the secret key, and the seed
  // that determines the WOTS keypairs in the short-time subtree. Note that the
  // WOTS keypairs in the short-time subtree depend on the leaf index that
  // holds the short-time subtree.
  unsigned int msg_hash_seed_input_size = SK_RAND_SEED_BYTES + SEED_BYTES;
  unsigned char msg_hash_seed_input[msg_hash_seed_input_size];
  memcpy(msg_hash_seed_input                     , sk, SK_RAND_SEED_BYTES);
  memcpy(msg_hash_seed_input + SK_RAND_SEED_BYTES, seed, SEED_BYTES);

  unsigned int msg_hash_input_size = MESSAGE_HASH_SEED_BYTES + HASH_BYTES;
  unsigned char msg_hash_input[msg_hash_input_size];

#if MESSAGE_HASH_SEED_BYTES != HASH_BYTES
#error "Only implemented for MESSAGE_HASH_SEED_BYTES == HASH_BYTES"
#endif
  varlen_hash(msg_hash_input, msg_hash_seed_input, msg_hash_seed_input_size);
  memcpy(context.message_hash_seed, msg_hash_input, MESSAGE_HASH_SEED_BYTES);

  memcpy(msg_hash_input + MESSAGE_HASH_SEED_BYTES, root, HASH_BYTES);

  unsigned char m_h[MSGHASH_BYTES];
  msg_hash(m_h, msg_hash_input, msg_hash_input_size);

  horst_sign(context.horst_signature, root, &horst_sigbytes, seed, addr_bytes, m_h);

  *clen = 0;
  int err = sign_leaf(context.horst_signature, N_LEVELS,
                      context.wots_signatures, clen,
                      sk,
                      addr_bytes);
  if(err) return err;

  *clen = CRYPTO_CONTEXTBYTES;
  return 0;
}

int crypto_sign_full(unsigned char *m, unsigned long long mlen,
                     unsigned char *context_bytes, unsigned long long *clen,
                     unsigned char *sig, unsigned long long *slen,
                     const unsigned char *sk)
{
  // Do whatever needs to happen for crypto_sign_update
  int res = crypto_sign_update(m, mlen, context_bytes, clen, sig, slen, sk);
  if(res) {
    return res;
  }
  unsigned char* sigp = sig  + *slen;

  struct batch_context context = init_batch_context(context_bytes);

  // Copy the remaining SPHINCS signature to the signature buffer
  memcpy(sigp, context.horst_signature, HORST_SIGBYTES);
  sigp += HORST_SIGBYTES;

  memcpy(sigp, context.wots_signatures,
         N_LEVELS*WOTS_SIGBYTES + TOTALTREE_HEIGHT*HASH_BYTES);
  sigp += N_LEVELS*WOTS_SIGBYTES + TOTALTREE_HEIGHT*HASH_BYTES;

  *slen = CRYPTO_BYTES;

  return 1;
}

int crypto_sign_update(unsigned char *m, unsigned long long mlen,
                       unsigned char *context_bytes, unsigned long long *clen,
                       unsigned char *sig, unsigned long long *slen,
                       const unsigned char *sk)
{
  unsigned char* sigp = sig;
  struct batch_context context = init_batch_context(context_bytes);

  // Get the current leafidx from the context
  unsigned long subtree_leafidx = *context.next_subtree_leafidx;

  // Store the used leaf idx in the signature
  memcpy(sigp, (unsigned char*) &subtree_leafidx, sizeof(unsigned long));
  sigp += sizeof(unsigned long);

  // Update the context so that the next signature uses the following leafidx
  int increment_res = increment_context(context_bytes);
  if (increment_res) {
    return increment_res;
  }

  // Sign the message with the WOTS secret key at the given leafidx of the
  // short-time subtree
  // Hash the message to HASH_BYTES
  unsigned char msg_hash[HASH_BYTES];
  varlen_hash(msg_hash, m, mlen);

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = N_LEVELS + 1;
  *address.subtree_address = *context.leafidx;
  *address.subtree_node = subtree_leafidx;

  unsigned char seed[SEED_BYTES];
  get_seed(seed, sk, addr_bytes);
  const unsigned char* public_seed = get_public_seed_from_sk(sk);

  wots_sign(sigp, msg_hash, seed, public_seed, addr_bytes);
  sigp += WOTS_SIGBYTES;
  *slen += WOTS_SIGBYTES;

  // Store the authentication path of that signature in the signature buffer
  compute_authpath_wots(msg_hash, sigp, addr_bytes, sk, SUBTREE_HEIGHT,
                        public_seed);
  sigp += SUBTREE_HEIGHT*HASH_BYTES;
  *slen += SUBTREE_HEIGHT*HASH_BYTES;

  return 0;
}

int crypto_sign_open_full(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
  // Verify the signature of the message by restoring the root of the short-time
  // subtree, using crypto_sign_open_update

  // Verify the root of the short-time subtree by restoring the root of the
  // SPHINCS tree with the rest of the signature

  // Verify that the restored root is indeed the expected public key

  return 0;
}

int crypto_sign_open_update(unsigned char *m, unsigned long long *mlen,
                            const unsigned char* context, unsigned long long *clen,
                            const unsigned char* sig, unsigned long long smlen,
                            const unsigned char *pk)
{
  // Restore the root of the short-time subtree, using the message and the given
  // authentication path

  // Verify that that root equals the expected root

  return 0;
}
