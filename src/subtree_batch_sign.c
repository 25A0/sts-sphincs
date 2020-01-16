#include "subtree_batch_sign.h"
#include "hash.h"
#include "tree.h"
#include "wots.h"
#include "horst.h"
#include "hash_address.h"
#include "randombytes.h"
#include "zerobytes.h"
#include "crypto_hash_blake512.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct batch_sts{
  // The seed that produces the secret keys of the WOTS key pairs that form the
  // leaves of the short-time subtree
  unsigned char* subtree_sk_seed;

  // The index of the leaf in the subtree that should be used to sign the next
  // message
  TSUBTREE_IDX* next_subtree_leafidx;

  // The public keys of the WOTS key pairs in the short-time subtree
  unsigned char* wots_kps;

  // The leaf index that is parent to the short-time subtree
  unsigned long long* leafidx;

  // The HORST signature that signs the root of the short-time subtree
  unsigned char* horst_signature;

  // The N_LEVELS WOTS signatures that sign level_0_hash under the
  // key pair that was used to generate this sts
  unsigned char* wots_signatures;

};

const struct batch_sts init_batch_sts(unsigned char *bytes) {
  struct batch_sts sts;
  int offset = 0;

  sts.subtree_sk_seed = bytes + offset;
  offset += SEED_BYTES;

  sts.next_subtree_leafidx = (TSUBTREE_IDX*) (bytes + offset);
  offset += sizeof(TSUBTREE_IDX);

  sts.wots_kps = bytes + offset;
  offset += (1 << SUBTREE_HEIGHT) * HASH_BYTES;

  sts.leafidx = (unsigned long long*) (bytes + offset);
  offset += (TOTALTREE_HEIGHT+7)/8;

  sts.horst_signature = bytes + offset;
  offset += STS_HORST_SIGBYTES;

  sts.wots_signatures = bytes + offset;
  offset += N_LEVELS * WOTS_SIGBYTES +
            (TOTALTREE_HEIGHT - SUBTREE_HEIGHT) * HASH_BYTES;

  assert(offset == CRYPTO_STS_BYTES);

  return sts;
}

const unsigned char* get_public_seed_from_pk(const unsigned char* pk) {
  return pk + HASH_BYTES;
}

const unsigned char* get_public_seed_from_sk(const unsigned char* sk) {
  return sk + SEED_BYTES;
}

/*
 * Format pk: [root|public seed]
 * Format sk: [seed|public seed|secret seed]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  randombytes(sk,CRYPTO_SECRETKEYBYTES);

  // Initialization of top-subtree address
  unsigned char address[ADDR_BYTES];
  set_type(address, SPHINCS_ADDR);
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = N_LEVELS - 1;
  *addr.subtree_address = 0;
  *addr.subtree_node = 0;

  // Construct top subtree
  treehash(pk, SUBTREE_HEIGHT, sk, address, get_public_seed_from_sk(sk));

  // Copy public seed
  memcpy(pk + HASH_BYTES, sk + SEED_BYTES, PUBLIC_SEED_BYTES);

  return 0;
}

// The configuration that will be used for the WOTS signature that signs
// the message hash. Since the message hash has 64 bytes rather than 32,
// L and L1 need to be adapted.
const struct wots_config sts_wots_config = { STS_WOTS_L,
                                             STS_WOTS_L1,
                                             STS_WOTS_LOG_L,
                                             STS_WOTS_SIGBYTES
};

// The configuration that will be used for the HORST signature that signs
// the root of the short-time subtree. Since that root only has 32 bytes,
// HORST can be used with k=16 instead of 32, which reduces the signature size
// and speeds up signing and verification.
const struct horst_config sts_horst_config = {STS_HORST_K, STS_HORST_SIGBYTES};

static int increment_sts(unsigned char *sts_bytes)
{
  struct batch_sts sts = init_batch_sts(sts_bytes);

  // Make sure that the next leafidx actually exists in the
  // short-time subtree
  if(*sts.next_subtree_leafidx < (1 << SUBTREE_HEIGHT)) {
    // Increment the leafidx that will be used for the next leaf
    (*sts.next_subtree_leafidx)++;
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

int crypto_sts_init(unsigned char *sts_buffer, const unsigned char *sk, long long user_leaf_idx)
{
  struct batch_sts sts = init_batch_sts(sts_buffer);

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

    *sts.leafidx = (rnd[next_unused_entropy++] &
                        (((unsigned long long) 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT)) - 1));
  } else if(user_leaf_idx < 0) {
    // Other negative leaf indices are considered an error.
    // If someone tried to iterate through all leaves and caused an overflow,
    // this case would catch that, instead of starting to use random leaves.
    return -1;
  } else if(user_leaf_idx >= (long long) 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT) ) {
    // This index is not a valid subtree index.
    return -2;
  } else {
    *sts.leafidx = user_leaf_idx;
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

  // Store that secret key in the sts
  assert(SEED_BYTES % sizeof(unsigned long long) == 0);
  memcpy(sts.subtree_sk_seed, rnd + next_unused_entropy, SEED_BYTES);
  next_unused_entropy += SEED_BYTES / sizeof(unsigned long long);

  // Initialize the sts to use leaf 0 of the short-time subtree
  *sts.next_subtree_leafidx = (unsigned long) 0;

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = 0;
  *address.subtree_address = *sts.leafidx;
  *address.subtree_node = *sts.next_subtree_leafidx;

  // Build the root of the short-time subtree
  unsigned char root[HASH_BYTES];
  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  sts_tree_hash_conf(root,
                     sts.wots_kps,
                     SUBTREE_HEIGHT,
                     sts.subtree_sk_seed,
                     addr_bytes,
                     public_seed,
                     sts_wots_config);
  // Create signature for that root at the given leafidx
  // And store that signature in the sts
  *address.subtree_layer = N_LEVELS; // special layer index for HORST
  *address.subtree_address = *sts.leafidx >> SUBTREE_HEIGHT;
  *address.subtree_node = *sts.leafidx % (1<<SUBTREE_HEIGHT);

  unsigned long long horst_sigbytes;
  unsigned char seed[SEED_BYTES];
  get_seed(seed, sk, addr_bytes);

  unsigned char horst_root[HASH_BYTES];
  horst_sign_conf(sts.horst_signature, horst_root, &horst_sigbytes, seed,
                  addr_bytes, root, HASH_BYTES, sts_horst_config);

  *address.subtree_layer = 1;
  unsigned long long clen = 0;

  int err = sign_leaf(horst_root, N_LEVELS - 1,
                      sts.wots_signatures, &clen,
                      sk,
                      addr_bytes);
  if(err) return err;

  return 0;
}

long long crypto_sts_remaining_uses(unsigned char *sts_bytes)
{
  struct batch_sts sts = init_batch_sts(sts_bytes);

  return (1 << SUBTREE_HEIGHT) - *sts.next_subtree_leafidx;
}

int crypto_sign_update(const unsigned char *m, unsigned long long mlen,
                       unsigned char *sts_bytes,
                       unsigned char *sig, unsigned long long *slen,
                       const unsigned char *sk)
{
  unsigned char* sigp = sig;
  struct batch_sts sts = init_batch_sts(sts_bytes);

  // Get the current leafidx from the sts
  unsigned long subtree_leafidx = *sts.next_subtree_leafidx;

  // Store the used leaf idx in the signature
  memcpy(sigp, (unsigned char*) &subtree_leafidx, sizeof(unsigned long));
  sigp += sizeof(unsigned long);
  *slen += sizeof(unsigned long);

  // Update the sts so that the next signature uses the following leafidx
  int increment_res = increment_sts(sts_bytes);
  if (increment_res) {
    return increment_res;
  }

  // Generate an address for this subtree
  unsigned char addr_bytes[ADDR_BYTES];
  zerobytes(addr_bytes, ADDR_BYTES);
  struct hash_addr address = init_hash_addr(addr_bytes);
  set_type(addr_bytes, SPHINCS_ADDR);
  *address.subtree_layer = 0;
  *address.subtree_address = *sts.leafidx;
  *address.subtree_node = subtree_leafidx;

  unsigned char seed[SEED_BYTES];
  // Note that the WOTS seed is generated from the seed stored in the short-time
  // sts, and not from the secret key.
  get_seed(seed, sts.subtree_sk_seed, addr_bytes);

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

  wots_sign_conf(sigp, m_h, seed, public_seed, addr_bytes, sts_wots_config);
  sigp += STS_WOTS_SIGBYTES;
  *slen += STS_WOTS_SIGBYTES;

  // Store the authentication path of that signature in the signature buffer
  // Note that the subtree seed is passed to this function instead of the
  // secret key. This is so that WOTS key pairs can be generated based on
  // that seed, rather than the secret key. Otherwise the key pairs
  // would be the same for each short-time state.
  compute_authpath(m_h, sigp, addr_bytes, sts.wots_kps,
                   sts.subtree_sk_seed, SUBTREE_HEIGHT, public_seed);
  sigp += SUBTREE_HEIGHT*HASH_BYTES;
  *slen += SUBTREE_HEIGHT*HASH_BYTES;

  return 0;
}

int crypto_sts_sign(const unsigned char *m, unsigned long long mlen,
                    unsigned char *sts_bytes,
                    unsigned char *sig, unsigned long long *slen,
                    const unsigned char *sk)
{
  unsigned char* sigp = sig;
  struct batch_sts sts = init_batch_sts(sts_bytes);

  // Start off by writing the used leaf idx to the signature
  memcpy(sigp, (unsigned char*) sts.leafidx, sizeof(unsigned long long));
  sigp += sizeof(unsigned long long);

  // Do whatever needs to happen for crypto_sign_update
  *slen = 0;
  int res = crypto_sign_update(m, mlen, sts_bytes, sigp, slen, sk);
  if(res) {
    return res;
  }
  assert(*slen == sizeof(unsigned long) + MESSAGE_HASH_SEED_BYTES +
         STS_WOTS_SIGBYTES + SUBTREE_HEIGHT*HASH_BYTES);
  sigp += *slen;

  // Copy the remaining SPHINCS signature to the signature buffer

  memcpy(sigp, sts.horst_signature, sts_horst_config.horst_sigbytes);
  sigp += sts_horst_config.horst_sigbytes;

  memcpy(sigp, sts.wots_signatures,
         (N_LEVELS -  1)*WOTS_SIGBYTES +
         (TOTALTREE_HEIGHT - SUBTREE_HEIGHT)*HASH_BYTES);
  sigp += (N_LEVELS - 1)*WOTS_SIGBYTES +
          (TOTALTREE_HEIGHT - SUBTREE_HEIGHT)*HASH_BYTES;

  *slen = CRYPTO_BYTES;

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
  *address.subtree_layer = 0;
  *address.subtree_address = leafidx;
  *address.subtree_node = subtree_leafidx;

  // The public key components will be stored in this buffer
  unsigned char wots_pk[sts_wots_config.wots_l * HASH_BYTES];

  wots_verify_conf(wots_pk, sigp, m_h, public_seed, addr_bytes, sts_wots_config);
  sigp += STS_WOTS_SIGBYTES;
  slen -= STS_WOTS_SIGBYTES;

  // Now construct an L-tree from that
  unsigned char pk_hash[HASH_BYTES];
  l_tree_conf(pk_hash, wots_pk, addr_bytes, public_seed, sts_wots_config);

  // validate_authpath(root, pkhash, leafidx & 0x1f, sigp, tpk, SUBTREE_HEIGHT);
  validate_authpath(level_0_hash, pk_hash, addr_bytes, public_seed, sigp,
                    SUBTREE_HEIGHT);
  sigp += HASH_BYTES * SUBTREE_HEIGHT;
  slen -= HASH_BYTES * SUBTREE_HEIGHT;

  assert(slen == 0);

  return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
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
                                    STS_WOTS_SIGBYTES +
                                    HASH_BYTES * SUBTREE_HEIGHT;

  int res =  restore_subtree_root(m, mlen, sigp, subtree_slen, leafidx,
                                  public_seed, restored_subtree_root);
  if(res) return res;

  // Move the signature pointer by the number of bytes that were consumed
  // by restore_subtree_root.
  sigp += subtree_slen;

  // Verify the root of the short-time subtree by restoring the root of the
  // SPHINCS tree with the rest of the signature

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
  res = horst_verify_conf(leaf,
                          sigp,
                          addr_bytes,
                          restored_subtree_root, HASH_BYTES,
                          sts_horst_config);
  if(res) return res;
  sigp += sts_horst_config.horst_sigbytes;
  smlen -= sts_horst_config.horst_sigbytes;

  *address.subtree_layer = 1;

  // Restore the root of the hypertree
  res = verify_leaf(leaf, N_LEVELS - 1,
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

// Also implement the standard API for signing messages
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk)
{
  unsigned char sts[CRYPTO_STS_BYTES];

  int res = crypto_sts_init(sts, sk, -1);
  if(res != 0) return res;

  return crypto_sts_sign(m, mlen, sts, sm, smlen, sk);
}
