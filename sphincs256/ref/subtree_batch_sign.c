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

  unsigned char m_h[MSGHASH_BYTES];
  msg_hash(m_h, root, HASH_BYTES);

  unsigned char horst_root[HASH_BYTES];
  horst_sign(context.horst_signature, horst_root, &horst_sigbytes, seed,
             addr_bytes, m_h);

  *address.subtree_layer = 0;
  *clen = 0;

  int err = sign_leaf(horst_root, N_LEVELS,
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
  unsigned char* sigp = sig;
  struct batch_context context = init_batch_context(context_bytes);

  // Start off by writing the used leaf idx to the signature
  memcpy(sigp, (unsigned char*) context.leafidx, sizeof(unsigned long long));
  sigp += sizeof(unsigned long long);

  // Do whatever needs to happen for crypto_sign_update
  *slen = 0;
  int res = crypto_sign_update(m, mlen, context_bytes, clen, sigp, slen, sk);
  if(res) {
    return res;
  }
  assert(*slen == sizeof(unsigned long) + MESSAGE_HASH_SEED_BYTES +
         WOTS_SIGBYTES + STS_SUBTREE_HEIGHT*HASH_BYTES);
  sigp += *slen;

  // Copy the remaining SPHINCS signature to the signature buffer

  memcpy(sigp, context.horst_signature, HORST_SIGBYTES);
  sigp += HORST_SIGBYTES;

  memcpy(sigp, context.wots_signatures,
         N_LEVELS*WOTS_SIGBYTES + TOTALTREE_HEIGHT*HASH_BYTES);
  sigp += N_LEVELS*WOTS_SIGBYTES + TOTALTREE_HEIGHT*HASH_BYTES;

  *slen = CRYPTO_BYTES;

  return 0;
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
  *slen += sizeof(unsigned long);

  // Update the context so that the next signature uses the following leafidx
  int increment_res = increment_context(context_bytes);
  if (increment_res) {
    return increment_res;
  }

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = N_LEVELS + 1;
  *address.subtree_address = *context.leafidx;
  *address.subtree_node = subtree_leafidx;

  unsigned char seed[SEED_BYTES];
  // Note that the WOTS seed is generated from the seed stored in the short-time
  // context, and not from the secret key.
  get_seed(seed, context.subtree_sk_seed, addr_bytes);

  // The message hash seed depends on the seed in the secret key, and the seed
  // that determines the WOTS keypairs in the short-time subtree. Note that the
  // WOTS keypairs in the short-time subtree depend on the leaf index that
  // holds the short-time subtree.
  unsigned int msg_hash_seed_input_size = SK_RAND_SEED_BYTES + SEED_BYTES;
  unsigned char msg_hash_seed_input[msg_hash_seed_input_size];
  memcpy(msg_hash_seed_input                     , sk, SK_RAND_SEED_BYTES);
  memcpy(msg_hash_seed_input + SK_RAND_SEED_BYTES, seed, SEED_BYTES);

  unsigned int msg_hash_input_size = MESSAGE_HASH_SEED_BYTES + mlen;
  unsigned char msg_hash_input[msg_hash_input_size];

#if MESSAGE_HASH_SEED_BYTES != HASH_BYTES
#error "Only implemented for MESSAGE_HASH_SEED_BYTES == HASH_BYTES"
#endif
  varlen_hash(msg_hash_input, msg_hash_seed_input, msg_hash_seed_input_size);
  memcpy(sigp, msg_hash_input, MESSAGE_HASH_SEED_BYTES);
  sigp += MESSAGE_HASH_SEED_BYTES;
  *slen += MESSAGE_HASH_SEED_BYTES;

  memcpy(msg_hash_input + MESSAGE_HASH_SEED_BYTES, m, mlen);

  unsigned char m_h[MSGHASH_BYTES];
  zerobytes(m_h, MSGHASH_BYTES);
  msg_hash(m_h, msg_hash_input, msg_hash_input_size);
  // TODO: currently, WOTS will only use the first 32 bytes of the 64 byte hash

  // Sign the message with the WOTS secret key at the given leafidx of the
  // short-time subtree

  const unsigned char* public_seed = get_public_seed_from_sk(sk);

  wots_sign(sigp, m_h, seed, public_seed, addr_bytes);
  sigp += WOTS_SIGBYTES;
  *slen += WOTS_SIGBYTES;

  // Store the authentication path of that signature in the signature buffer
  // Note that the subtree seed is passed to this function instead of the
  // secret key. This is so that WOTS key pairs can be generated based on
  // that seed, rather than the secret key. Otherwise the key pairs
  // would be the same for each short-time state.
  compute_authpath_wots(m_h, sigp, addr_bytes, context.subtree_sk_seed,
                        STS_SUBTREE_HEIGHT,
                        public_seed);
  sigp += STS_SUBTREE_HEIGHT*HASH_BYTES;
  *slen += STS_SUBTREE_HEIGHT*HASH_BYTES;

  return 0;
}

/* Restores the root of the short-time subtree from message m and signature sig
 */
int restore_subtree_root(unsigned char *m, unsigned long long *mlen,
                         const unsigned char* sig, unsigned long long slen,
                         unsigned long long leafidx,
                         const unsigned char* public_seed,
                         unsigned char* level_0_hash)
{
  const unsigned char* sigp = sig;

  // Read the used leaf idx from the signature
  unsigned long subtree_leafidx = *((unsigned long*) sigp);
  sigp += sizeof(unsigned long);
  slen -= sizeof(unsigned long);

  unsigned int msg_hash_input_size = MESSAGE_HASH_SEED_BYTES + *mlen;
  unsigned char msg_hash_input[msg_hash_input_size];

  memcpy(msg_hash_input, sigp, MESSAGE_HASH_SEED_BYTES);
  sigp += MESSAGE_HASH_SEED_BYTES;
  slen -= MESSAGE_HASH_SEED_BYTES;

  memcpy(msg_hash_input + MESSAGE_HASH_SEED_BYTES, m, *mlen);

  unsigned char m_h[MSGHASH_BYTES];
  zerobytes(m_h, MSGHASH_BYTES);
  msg_hash(m_h, msg_hash_input, msg_hash_input_size);
  // TODO: currently, WOTS will only use the first 32 bytes of the 64 byte hash

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = N_LEVELS + 1;
  *address.subtree_address = leafidx;
  *address.subtree_node = subtree_leafidx;

  // The public key components will be stored in this buffer
  unsigned char wots_pk[WOTS_L * HASH_BYTES];

  wots_verify(wots_pk, sigp, m_h, public_seed, addr_bytes);
  sigp += WOTS_SIGBYTES;
  slen -= WOTS_SIGBYTES;

  // Now construct an L-tree from that
  unsigned char pk_hash[HASH_BYTES];
  l_tree(pk_hash, wots_pk, addr_bytes, public_seed);

  // validate_authpath(root, pkhash, leafidx & 0x1f, sigp, tpk, SUBTREE_HEIGHT);
  validate_authpath(level_0_hash, pk_hash, addr_bytes, public_seed, sigp,
                    STS_SUBTREE_HEIGHT);
  sigp += HASH_BYTES * STS_SUBTREE_HEIGHT;
  slen -= HASH_BYTES * STS_SUBTREE_HEIGHT;

  assert(slen == 0);

  return 0;
}

int crypto_sign_open_full(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
  const unsigned char* sigp = sm;

  // Read the subtree leaf idx from the signature
  unsigned long long leafidx = *((unsigned long long*) sigp);
  sigp += sizeof(unsigned long long);
  smlen -= sizeof(unsigned long long);

  // Restore the root of the short-time subtree
  unsigned char restored_subtree_root[HASH_BYTES];
  const unsigned char* public_seed = get_public_seed_from_pk(pk);

  // The number of bytes that can be consumed by restore_subtree_root.
  unsigned long long subtree_slen = sizeof(unsigned long) +
                                    MESSAGE_HASH_SEED_BYTES +
                                    WOTS_SIGBYTES +
                                    HASH_BYTES * STS_SUBTREE_HEIGHT;

  int res =  restore_subtree_root(m, mlen, sigp, subtree_slen, leafidx,
                                  public_seed, restored_subtree_root);
  if(res) return res;

  // Move the signature pointer by the number of bytes that were consumed
  // by restore_subtree_root.
  sigp += subtree_slen;

  // Verify the root of the short-time subtree by restoring the root of the
  // SPHINCS tree with the rest of the signature
  unsigned char message_hash[MSGHASH_BYTES];
  msg_hash(message_hash, restored_subtree_root, HASH_BYTES);

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = N_LEVELS;
  *address.subtree_address = leafidx >> SUBTREE_HEIGHT;
  *address.subtree_node = leafidx % (1<<SUBTREE_HEIGHT);

  // Restore the HORST public key
  unsigned char leaf[HASH_BYTES];
  res = horst_verify(leaf,
                     sigp,
                     addr_bytes,
                     message_hash);
  if(res) return res;
  sigp += HORST_SIGBYTES;
  smlen -= HORST_SIGBYTES;

  *address.subtree_layer = 0;

  // Restore the root of the hypertree
  res = verify_leaf(leaf, N_LEVELS,
                    sigp, smlen,
                    pk,
                    addr_bytes);
  if(res) return res;

  // Verify that the restored root is indeed the expected public key
  int i;
  for(i=0; i < HASH_BYTES; i++) {
    if(pk[i] != leaf[i]) return 1;
  }

  return 0;
}
