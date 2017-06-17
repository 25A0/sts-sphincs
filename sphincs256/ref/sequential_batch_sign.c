#include "sign.h"
#include "batch_sign.h"
#include "sequential_batch_api.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "randombytes.h"
#include "zerobytes.h"
#include "params.h"
#include "wots.h"
#include "horst.h"
#include "hash.h"
#include "crypto_hash_blake512.h"
#include "hash_address.h"
#include "tree.h"

#define BIGINT_BYTES ((TOTALTREE_HEIGHT-SUBTREE_HEIGHT+7)/8)

#if (TOTALTREE_HEIGHT-SUBTREE_HEIGHT) > 64
#error "TOTALTREE_HEIGHT-SUBTREE_HEIGHT must be at most 64" 
#endif

struct batch_context{
  // The leaf index that should be used for the next signature
  unsigned long long* next_leafidx;

  // The N_LEVELS-1 WOTS signatures that sign the hash of the subtree on level
  // 0 under the key pair that was used to generate this context
  unsigned char* signatures;
};

const struct batch_context init_batch_context(unsigned char* bytes) {
  struct batch_context context;
  int offset = 0;

  context.next_leafidx = (unsigned long long*) bytes + offset;
  offset += (TOTALTREE_HEIGHT+7)/8;

  context.signatures = bytes + offset;

  return context;
}

/*
 * Increment whatever identifier determines which leaf is used to sign
 * the next message
 */
static int increment_context(unsigned char *context_bytes) {
  struct batch_context context = init_batch_context(context_bytes);

  // Increment the leafidx that indicates which leaf should be used
  // to sign the message
  unsigned long long leafidx = *context.next_leafidx;

  // Check that this leafidx can still be incremented.
  // This is the case as long as the current leafidx does not point
  // to the last leaf of its subtree.
  unsigned long long first_leaf = leafidx - (leafidx % (1<<SUBTREE_HEIGHT));
  if(leafidx  - first_leaf == (1<<SUBTREE_HEIGHT) - 1) return -42;

  // We also need to make sure that we never accidentially use a leaf that
  // is not even part of the tree.
  if(leafidx > ((unsigned long long)1 << TOTALTREE_HEIGHT) - 1) return -13;

  // Otherwise we can safely increment the leafidx.
  leafidx += 1;

  // Write new leafidx to context
  *context.next_leafidx = leafidx;

  return 0;
}

int crypto_context_init(unsigned char *context_bytes, unsigned long long *clen,
                        const unsigned char *sk, long long subtree_idx)
{
  *clen = 0;

  unsigned long long leafidx;
  // If the subtree index is -1 then we choose a random subtree, otherewise
  // we use the one provided by the user
  if(subtree_idx < 0) {
    // ===============================
    // Generate a random subtree index
    // ===============================

    unsigned char scratch[SK_RAND_SEED_BYTES + SEED_BYTES];
    memcpy(scratch, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES,
           SK_RAND_SEED_BYTES);
    int err = get_system_entropy(scratch + SK_RAND_SEED_BYTES, SEED_BYTES);
    if(err) return err;
    unsigned long long rnd[8];
    crypto_hash_blake512((unsigned char*) rnd, scratch, SK_RAND_SEED_BYTES + SEED_BYTES);
    zerobytes(scratch, SK_RAND_SEED_BYTES + SEED_BYTES);

    // The lower 60 bit % (2^SUBTREE_HEIGHT) form the leafidx.
    // This comes down to picking a random subtree on the lowest level,
    // and picking the left-most leaf in that subtree
    leafidx = (rnd[0] & 0xfffffffffffffff);
    leafidx -= leafidx % (1<<SUBTREE_HEIGHT);
  } else if(subtree_idx >= (long long) 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT) ) {
    // This index is not a valid subtree index.
    return -1;
  } else {
    // Shifting the subtree_idx to the left by the subtree height turns
    // the subtree index into the index of its left-most leaf.
    // For example, the left-most leaf of subtree 1 has index 2^SUBTREE_HEIGHT.
    leafidx = subtree_idx << SUBTREE_HEIGHT;
  }

  struct batch_context context = init_batch_context(context_bytes);

  // ==============================================================
  // Write the current leafidx to the context
  // ==============================================================
  *context.next_leafidx = leafidx;
  *clen += (TOTALTREE_HEIGHT+7)/8;

  // ==============================================================
  // Construct the hash of the lowest tree, write it to the context
  // ==============================================================

  // This address points to the subtree described by leafidx
  unsigned char address_bytes[ADDR_BYTES];
  set_type(address_bytes, SPHINCS_ADDR);
  struct hash_addr address = init_hash_addr(address_bytes);
  *address.subtree_layer = 0;
  *address.subtree_address = leafidx>>SUBTREE_HEIGHT;
  *address.subtree_node = leafidx % (1 <<SUBTREE_HEIGHT);

  unsigned char* public_seed = get_public_seed_from_sk(sk);
  unsigned char level_0_hash[HASH_BYTES];
  treehash(level_0_hash, SUBTREE_HEIGHT, sk, address_bytes, public_seed);

  // ==============================================================
  // Write the upper N_LEVELS - 1 WOTS signatures to the context
  // ==============================================================
  set_type(address_bytes, SPHINCS_ADDR);
  parent(SUBTREE_HEIGHT, address);
  sign_leaf(level_0_hash, N_LEVELS - 1, context.signatures, clen, sk, address_bytes);

  return 0;
}

int crypto_sign_full(unsigned char *m, unsigned long long mlen,
                     unsigned char *context_bytes, unsigned long long *clen,
                     unsigned char *sig, unsigned long long *slen,
                     const unsigned char *sk)
{
  unsigned char* sigp = sig;
  *slen = 0;
  struct batch_context context = init_batch_context(context_bytes);

  // ==============================================================
  // Do whatever we do when we update a signature
  // ==============================================================
  unsigned long long uslen = 0;
  crypto_sign_update(m, mlen, context_bytes, clen, sigp, &uslen, sk);
  sigp += uslen;
  *slen += uslen;

  // ==============================================================
  // Copy remaining signatures from context
  // ==============================================================

  // Copy the WOTS signatures and auth paths for the upper N_LEVELS - 1
  // levels to the signature.
  // We assume that the sig pointer has been shifted forwards while
  // crypto_sign_update has written to it.
  memcpy(sigp, context.signatures,
         (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES));
  sigp += (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES);
  *slen += (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES);

  // Copy the message to the end of the signature
  memcpy(sigp, m, mlen);
  sigp += mlen;
  *slen += mlen;

  return 0;
}

int crypto_sign_update(unsigned char *m, unsigned long long mlen,
                       unsigned char *context_bytes, unsigned long long *clen,
                       unsigned char *sig_bytes, unsigned long long *slen,
                       const unsigned char *sk)
{
  *slen = 0;
  int i;

  unsigned char tsk[CRYPTO_SECRETKEYBYTES];
  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++)
    tsk[i] = sk[i];

  struct batch_context context = init_batch_context(context_bytes);
  struct signature sig = init_signature(sig_bytes);

  // Read leafidx from updated context
  unsigned long long leafidx = *context.next_leafidx;

  // ==========================================================================
  // Calculate and copy the message hash seed to the beginning of the signature
  // ==========================================================================

  // The message hash seed depends on:
  //  - the seed in the secret key, and
  //  - the message
  // shift scratch upwards so we can reuse msg later
  unsigned char* msg_hash_seed_input = sig_bytes + CRYPTO_BYTES - SK_RAND_SEED_BYTES;

  // Copy message to scratch backwards to handle m = sm overlap
  for(i=mlen;i>0;i--)
    msg_hash_seed_input[SK_RAND_SEED_BYTES+i-1] = m[i-1];

  // Copy secret random seed to scratch
  memcpy(msg_hash_seed_input, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES,
         SK_RAND_SEED_BYTES);

  unsigned long long rnd[8];
  crypto_hash_blake512((unsigned char*)rnd, msg_hash_seed_input,
                       SK_RAND_SEED_BYTES + mlen);

  unsigned char* msg_hash_seed = (unsigned char*) &rnd[2];
  memcpy(sig.message_hash_seed, msg_hash_seed, MESSAGE_HASH_SEED_BYTES);

  sig_bytes += MESSAGE_HASH_SEED_BYTES;
  *slen += MESSAGE_HASH_SEED_BYTES;

  // ==============================================================
  // Update leafidx. Return if we're out of leaves
  // ==============================================================

  int res = increment_context(context_bytes);
  if(res != 0) return res;

  // Write used leafidx to signature
  write_ull(sig.leafidx, leafidx, (TOTALTREE_HEIGHT+7)/8);

  sig_bytes += (TOTALTREE_HEIGHT+7)/8;
  *slen += (TOTALTREE_HEIGHT+7)/8;

  // ==============================================================
  // Hash message
  // ==============================================================
  unsigned char scratch[mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES];
  unsigned char* sp = scratch;
  memcpy(sp, msg_hash_seed, MESSAGE_HASH_SEED_BYTES);
  sp += MESSAGE_HASH_SEED_BYTES;

  const unsigned char *public_seed = get_public_seed_from_sk(sk);
  unsigned char root_address_bytes[ADDR_BYTES];
  // Initialization of top-subtree address
  set_type(root_address_bytes, SPHINCS_ADDR);
  struct hash_addr root_address = init_hash_addr(root_address_bytes);
  *root_address.subtree_layer = N_LEVELS - 1;
  *root_address.subtree_address = 0;
  *root_address.subtree_node = 0;

  treehash(sp, SUBTREE_HEIGHT, tsk, root_address_bytes, public_seed);
  sp += HASH_BYTES;
  memcpy(sp, public_seed, PUBLIC_SEED_BYTES);
  sp += PUBLIC_SEED_BYTES;
  memcpy(sp, m, mlen);

  unsigned char m_h[MSGHASH_BYTES];
  msg_hash(m_h, scratch, mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);

  // ==============================================================
  // Sign message with HORST
  // ==============================================================
  unsigned char address_bytes[ADDR_BYTES];
  struct hash_addr address = init_hash_addr(address_bytes);
  *address.subtree_layer = N_LEVELS;
  *address.subtree_address = leafidx >> SUBTREE_HEIGHT;
  *address.subtree_node = leafidx & ((1<<SUBTREE_HEIGHT)-1);

  unsigned char seed[SEED_BYTES];
  get_seed(seed, tsk, address_bytes);
  unsigned char root[HASH_BYTES];
  unsigned long long horst_sigbytes;
  horst_sign(sig.horst_signature, root, &horst_sigbytes, seed, address_bytes, m_h);

  sig_bytes += horst_sigbytes;
  *slen += horst_sigbytes;

  // ==============================================================
  // Create WOTS signature for lvl 0
  // ==============================================================
  *address.subtree_layer = 0;
  sign_leaf(root, 1, sig.wots_signatures, slen, tsk, address_bytes);

  // ==============================================================
  // The verifier already has a copy of the rest of the signature
  // ==============================================================
  return 0;
}

int crypto_sign_open_full(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
  // Should act the same way a normal signature works
  return crypto_sign_open(m, mlen, sm, smlen, pk);
}
