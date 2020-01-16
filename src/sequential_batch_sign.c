#include "sequential_batch_sign.h"

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
#include "entropy.h"

#define BIGINT_BYTES ((TOTALTREE_HEIGHT-SUBTREE_HEIGHT+7)/8)

#if (TOTALTREE_HEIGHT-SUBTREE_HEIGHT) > 64
#error "TOTALTREE_HEIGHT-SUBTREE_HEIGHT must be at most 64" 
#endif

struct batch_sts{
  // The leaf index that should be used for the next signature
  unsigned long long* next_leafidx;

  // The public keys of the WOTS key pairs. Cached to speed up signing.
  unsigned char* wots_pks;

  // The N_LEVELS-1 WOTS signatures that sign the hash of the subtree on level
  // 0 under the key pair that was used to generate this sts
  unsigned char* signatures;
};

const struct batch_sts init_batch_sts(unsigned char* bytes) {
  struct batch_sts sts;
  int offset = 0;

  sts.next_leafidx = (unsigned long long*) bytes + offset;
  offset += (TOTALTREE_HEIGHT+7)/8;

  sts.wots_pks = bytes + offset;
  offset += (1 << SUBTREE_HEIGHT) * HASH_BYTES;

  sts.signatures = bytes + offset;

  return sts;
}

struct signature {
  // The hash seed that was used to hash the message
  unsigned char* message_hash_seed;
  // The index of the HORST leaf that signed the message
  unsigned char* leafidx;
  // The HORST signature of the message
  unsigned char* horst_signature;
  // The WOTS signatures that verify the HORST signature under the used key pair
  unsigned char* wots_signatures;

  // The signature always contains a copy of the message at the very end
  unsigned char* message;
};

struct signature init_signature(unsigned char* bytes) {
  struct signature sig;
  unsigned long long offset = 0;

  sig.message_hash_seed = bytes + offset;
  offset += MESSAGE_HASH_SEED_BYTES;

  sig.leafidx = bytes + offset;
  offset += (TOTALTREE_HEIGHT+7)/8;

  sig.horst_signature = bytes + offset;
  offset += HORST_SIGBYTES;

  sig.wots_signatures = bytes + offset;

  // The message is always at the very end of the signature
  sig.message = bytes + CRYPTO_BYTES;

  return sig;
}

const unsigned char* get_public_seed_from_pk(const unsigned char* pk) {
  return pk + HASH_BYTES;
}

const unsigned char* get_public_seed_from_sk(const unsigned char* sk) {
  return sk + SEED_BYTES;
}

// Since the code should ideally work across systems with different endianness,
// this function defines unambiguously how an ull is serialized.
void write_ull(unsigned char* buf, const unsigned long long ull,
                      const unsigned int bytes) {
  int i;
  for(i=0;i<bytes;i++)
    buf[i] = (ull >> 8*i) & 0xff;
}

unsigned long long
read_ull(unsigned char* buf, const unsigned int bytes) {
  unsigned long long res = 0;
  int i;
  for(i=0;i<bytes;i++)
    res |= (((unsigned long long)buf[i]) << 8*i);
  return res;
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

/*
 * Increment whatever identifier determines which leaf is used to sign
 * the next message
 */
static int increment_sts(unsigned char *sts_bytes) {
  struct batch_sts sts = init_batch_sts(sts_bytes);

  // Increment the leafidx that indicates which leaf should be used
  // to sign the message
  unsigned long long leafidx = *sts.next_leafidx;

  // Check for the sentinel value that indicates that the end of the subtree
  // was reached with the last signature
  if(leafidx == (unsigned long long) -1) {
    return -42;
  }

  // We need to make sure that we never accidentially use a leaf that
  // is not even part of the tree.
  if(leafidx > ((unsigned long long)1 << TOTALTREE_HEIGHT) - 1) return -13;

  // Check that this leafidx can still be incremented.
  // This is the case as long as the current leafidx does not point
  // to the last leaf of its subtree.
  unsigned long long first_leaf = leafidx - (leafidx % (1<<SUBTREE_HEIGHT));
  if(leafidx  - first_leaf == (1<<SUBTREE_HEIGHT) - 1) {
    leafidx = (unsigned long long) -1;
  } else {
    // Otherwise we can safely increment the leafidx.
    leafidx += 1;
  }

  // Write new leafidx to sts
  *sts.next_leafidx = leafidx;

  return 0;
}

int crypto_sts_init(unsigned char *sts_bytes, const unsigned char *sk, long long subtree_idx)
{
  unsigned long long clen = 0;

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

  struct batch_sts sts = init_batch_sts(sts_bytes);

  // ==============================================================
  // Write the current leafidx to the sts
  // ==============================================================
  *sts.next_leafidx = leafidx;
  clen += (TOTALTREE_HEIGHT+7)/8;

  // ==============================================================
  // Construct the hash of the lowest tree, write it to the sts
  // ==============================================================

  // This address points to the subtree described by leafidx
  unsigned char address_bytes[ADDR_BYTES];
  set_type(address_bytes, SPHINCS_ADDR);
  struct hash_addr address = init_hash_addr(address_bytes);
  *address.subtree_layer = 0;
  *address.subtree_address = leafidx>>SUBTREE_HEIGHT;
  *address.subtree_node = leafidx % (1 <<SUBTREE_HEIGHT);

  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  unsigned char level_0_hash[HASH_BYTES];
  // Compute root of lowest tree and WOTS public keys in the same pass
  sts_tree_hash_conf(level_0_hash, sts.wots_pks, SUBTREE_HEIGHT, sk,
                     address_bytes, public_seed, default_wots_config);

  // ==============================================================
  // Write the upper N_LEVELS - 1 WOTS signatures to the sts
  // ==============================================================
  set_type(address_bytes, SPHINCS_ADDR);
  parent(SUBTREE_HEIGHT, address);
  sign_leaf(level_0_hash, N_LEVELS - 1, sts.signatures, &clen, sk, address_bytes);

  return 0;
}

long long crypto_sts_remaining_uses(unsigned char *sts_bytes)
{
  struct batch_sts sts = init_batch_sts(sts_bytes);
  unsigned long long leafidx = *sts.next_leafidx;

  // Compute the index of the first leaf of the subtree containing leafidx
  unsigned long long leafidx_within_subtree = leafidx % (1<<SUBTREE_HEIGHT);
  return (1 << SUBTREE_HEIGHT) - leafidx_within_subtree;
}

int crypto_sign_update(const unsigned char *m, unsigned long long mlen,
                       unsigned char *sts_bytes,
                       unsigned char *sig_bytes, unsigned long long *slen,
                       const unsigned char *sk)
{
  *slen = 0;
  int i;

  unsigned char tsk[CRYPTO_SECRETKEYBYTES];
  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++)
    tsk[i] = sk[i];

  struct batch_sts sts = init_batch_sts(sts_bytes);
  struct signature sig = init_signature(sig_bytes);

  // Read leafidx from updated sts
  unsigned long long leafidx = *sts.next_leafidx;

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

  int res = increment_sts(sts_bytes);
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
  horst_sign(sig.horst_signature, root, &horst_sigbytes, seed, address_bytes,
             m_h, MSGHASH_BYTES);

  sig_bytes += horst_sigbytes;
  *slen += horst_sigbytes;

  // ==============================================================
  // Create WOTS signature for lvl 0
  // ==============================================================
  *address.subtree_layer = 0;
  get_seed(seed, sk, address_bytes);

  wots_sign(sig_bytes, root, seed, public_seed, address_bytes);
  sig_bytes += WOTS_SIGBYTES;
  *slen += WOTS_SIGBYTES;

  compute_authpath(root, sig_bytes,address_bytes, sts.wots_pks, sk,
                   SUBTREE_HEIGHT, public_seed);

  sig_bytes += SUBTREE_HEIGHT*HASH_BYTES;
  *slen += SUBTREE_HEIGHT*HASH_BYTES;

  parent(SUBTREE_HEIGHT, address);
  // sign_leaf(root, 1, sig.wots_signatures, slen, tsk, address_bytes);

  // ==============================================================
  // The verifier already has a copy of the rest of the signature
  // ==============================================================
  return 0;
}

int crypto_sts_sign(unsigned char *sig, unsigned long long *slen,
                    const unsigned char *m, unsigned long long mlen,
                    unsigned char *sts_bytes,
                    const unsigned char *sk)
{
  unsigned char* sigp = sig;
  *slen = 0;
  struct batch_sts sts = init_batch_sts(sts_bytes);

  // ==============================================================
  // Do whatever we do when we update a signature
  // ==============================================================
  unsigned long long uslen = 0;
  crypto_sign_update(m, mlen, sts_bytes, sigp, &uslen, sk);
  sigp += uslen;
  *slen += uslen;

  // ==============================================================
  // Copy remaining signatures from sts
  // ==============================================================

  // Copy the WOTS signatures and auth paths for the upper N_LEVELS - 1
  // levels to the signature.
  // We assume that the sig pointer has been shifted forwards while
  // crypto_sign_update has written to it.
  memcpy(sigp, sts.signatures,
         (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES));
  sigp += (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES);
  *slen += (N_LEVELS - 1) * (WOTS_SIGBYTES + SUBTREE_HEIGHT * HASH_BYTES);

  // Copy the message to the end of the signature
  memcpy(sigp, m, mlen);
  sigp += mlen;
  *slen += mlen;

  return 0;
}

// The body of this function is copied from sign.c. Since the signature
// has the exact same structure as a classic SPHINCS signature, we
// can use the exact same code.
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
  unsigned long long i;
  unsigned long long leafidx=0;
  unsigned char root[HASH_BYTES];
  unsigned char sig_bytes[CRYPTO_BYTES];
  unsigned char *sigp;
  unsigned char tpk[CRYPTO_PUBLICKEYBYTES];

  if(smlen < CRYPTO_BYTES)
    return -1;

  memcpy(sig_bytes, sm, CRYPTO_BYTES);
  struct signature sig_struct = init_signature(sig_bytes);

  unsigned char m_h[MSGHASH_BYTES];

  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++)
    tpk[i] = pk[i];

  // construct message hash
  {
    unsigned char R[MESSAGE_HASH_SEED_BYTES];

    memcpy(R, sig_struct.message_hash_seed, MESSAGE_HASH_SEED_BYTES);

    // Message length
    int len = smlen - CRYPTO_BYTES;

    unsigned char *scratch = m;


    memcpy(scratch + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES, sm + CRYPTO_BYTES, len);

    // cpy R
    memcpy(scratch, R, MESSAGE_HASH_SEED_BYTES);

    // cpy pub key
    memcpy(scratch + MESSAGE_HASH_SEED_BYTES, tpk, CRYPTO_PUBLICKEYBYTES);

    msg_hash(m_h, scratch, len + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);

  }
  sigp = sig_bytes;

  sigp += MESSAGE_HASH_SEED_BYTES;
  smlen -= MESSAGE_HASH_SEED_BYTES;

  leafidx = read_ull(sig_struct.leafidx, (TOTALTREE_HEIGHT+7)/8);

  unsigned char address[ADDR_BYTES];
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = N_LEVELS;
  *addr.subtree_address = leafidx >> SUBTREE_HEIGHT;
  *addr.subtree_node = leafidx % (1<<SUBTREE_HEIGHT);

  horst_verify(root,
               sig_struct.horst_signature,
               address,
               m_h, MSGHASH_BYTES);

  sigp += (TOTALTREE_HEIGHT+7)/8;
  smlen -= (TOTALTREE_HEIGHT+7)/8;
  
  sigp += HORST_SIGBYTES;
  smlen -= HORST_SIGBYTES;

  *addr.subtree_layer = 0;
  verify_leaf(root, N_LEVELS, sig_struct.wots_signatures, smlen, pk, address);

  for(i=0;i<HASH_BYTES;i++)
    if(root[i] != tpk[i])
      goto fail;
  
  *mlen = smlen;
  for(i=0;i<*mlen;i++)
    m[i] = m[i+MESSAGE_HASH_SEED_BYTES+CRYPTO_PUBLICKEYBYTES];

  return 0;
  
  
fail:
  *mlen = smlen;
  for(i=0;i<*mlen;i++)
    m[i] = 0;
  *mlen = -1;
  return -1;
}

// Also implement the standard API for signing messages
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk)
{
  unsigned char sts[CRYPTO_STS_BYTES];

  int res = crypto_sts_init(sts, sk, -1);
  if(res != 0) return res;

  return crypto_sts_sign(sm, smlen, m, mlen, sts, sk);
}
