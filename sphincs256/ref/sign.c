#include "crypto_sign.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "randombytes.h"
#include "zerobytes.h"
#include "params.h"
#include "wots.h"
#include "horst.h"
#include "hash.h"
#include "crypto_hash_blake512.h"
#include "hash_address.h"
#include "tree.h"
#include "sign.h"

#define BIGINT_BYTES ((TOTALTREE_HEIGHT-SUBTREE_HEIGHT+7)/8)

#if (TOTALTREE_HEIGHT-SUBTREE_HEIGHT) > 64
#error "TOTALTREE_HEIGHT-SUBTREE_HEIGHT must be at most 64" 
#endif

struct batch_context{
  // The leaf index that should be used for the next signature
  unsigned long long* next_leafidx;
  // The hash of the subtree on level 0.  All signatures created with this
  // context use a leaf which is a child of the subtree with this hash.
  unsigned char* level_0_hash;

  // The N_LEVELS-1 WOTS signatures that sign level_0_hash under the
  // key pair that was used to generate this context
  unsigned char* signatures;
};

static const struct batch_context init_batch_context(unsigned char* bytes) {
  struct batch_context context;
  int offset = 0;

  context.next_leafidx = (unsigned long long*) bytes + offset;
  offset += (TOTALTREE_HEIGHT+7)/8;

  context.level_0_hash = bytes + offset;
  offset += HASH_BYTES;

  context.signatures = bytes + offset;

  return context;
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

static struct signature init_signature(unsigned char* bytes) {
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

// Since the code should ideally work across systems with different endianness,
// this function defines unambiguously how an ull is serialized.
static inline void
write_ull(unsigned char* buf, const unsigned long long ull, const unsigned int bytes) {
  int i;
  for(i=0;i<bytes;i++)
    buf[i] = (ull >> 8*i) & 0xff;
}

static inline unsigned long long
read_ull(unsigned char* buf, const unsigned int bytes) {
  unsigned long long res = 0;
  int i;
  for(i=0;i<bytes;i++)
    res |= (((unsigned long long)buf[i]) << 8*i);
  return res;
}

static inline const unsigned char* get_public_seed_from_pk(const unsigned char* pk) {
  return pk + HASH_BYTES;
}

static inline const unsigned char* get_public_seed_from_sk(const unsigned char* sk) {
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

int crypto_sign(unsigned char *sm,
                unsigned long long *smlen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *sk)
{
  unsigned long long i;
  unsigned long long leafidx;
  unsigned char R[MESSAGE_HASH_SEED_BYTES];
  unsigned char m_h[MSGHASH_BYTES];
  unsigned long long rnd[8];
  unsigned long long horst_sigbytes;
  unsigned char root[HASH_BYTES];
  unsigned char seed[SEED_BYTES];
  unsigned char *pk;
  unsigned char tsk[CRYPTO_SECRETKEYBYTES];
  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  unsigned char address[ADDR_BYTES];
  struct hash_addr addr = init_hash_addr(address);

  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++)
    tsk[i] = sk[i];

  struct signature sig = init_signature(sm);

  // create leafidx deterministically
  {
    // shift scratch upwards so we can reuse msg later
    unsigned char* scratch = sm + CRYPTO_BYTES - SK_RAND_SEED_BYTES;

    // Copy message to scratch backwards to handle m = sm overlap
    for(i=mlen;i>0;i--)
      scratch[SK_RAND_SEED_BYTES+i-1] = m[i-1];
    // Copy secret random seed to scratch
    memcpy(scratch, tsk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES, SK_RAND_SEED_BYTES);

    crypto_hash_blake512((unsigned char*)rnd, scratch, SK_RAND_SEED_BYTES + mlen); //XXX: Why Blake 512?

    // wipe sk
    zerobytes(scratch,SK_RAND_SEED_BYTES);

#if TOTALTREE_HEIGHT != 60
#error "Implemented for TOTALTREE_HEIGHT == 60!"
#endif

    leafidx = rnd[0] & 0xfffffffffffffff;

#if MESSAGE_HASH_SEED_BYTES != 32
#error "Implemented for MESSAGE_HASH_SEED_BYTES == 32!"
#endif
    memcpy(R, &rnd[2], MESSAGE_HASH_SEED_BYTES);

    // prepare msg_hash
    scratch = sm + CRYPTO_BYTES - MESSAGE_HASH_SEED_BYTES - CRYPTO_PUBLICKEYBYTES;

    // cpy R
    memcpy(scratch, R, MESSAGE_HASH_SEED_BYTES);

    // Initialization of top-subtree address
    set_type(address, SPHINCS_ADDR);
    *addr.subtree_layer = N_LEVELS - 1;
    *addr.subtree_address = 0;
    *addr.subtree_node = 0;

    pk = scratch + MESSAGE_HASH_SEED_BYTES;

    treehash(pk, SUBTREE_HEIGHT, tsk, address, public_seed);

    // Include public seed
    memcpy(pk + HASH_BYTES, get_public_seed_from_sk(sk), PUBLIC_SEED_BYTES);

    // message already on the right spot
    msg_hash(m_h, scratch, mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);
  }

  *addr.subtree_layer = N_LEVELS;
  *addr.subtree_address = leafidx >> SUBTREE_HEIGHT;
  *addr.subtree_node = leafidx & ((1<<SUBTREE_HEIGHT)-1);

  *smlen = 0;

  // Write the message hash seed to the signature
  memcpy(sig.message_hash_seed, R, MESSAGE_HASH_SEED_BYTES);

  sm += MESSAGE_HASH_SEED_BYTES;
  *smlen += MESSAGE_HASH_SEED_BYTES;

  // Write the used leaf index to the signature
  write_ull(sig.leafidx, leafidx, (TOTALTREE_HEIGHT+7)/8);

  sm += (TOTALTREE_HEIGHT+7)/8;
  *smlen += (TOTALTREE_HEIGHT+7)/8;

  get_seed(seed, tsk, address);
  horst_sign(sig.horst_signature, root, &horst_sigbytes, seed, address, m_h);

  sm += horst_sigbytes;
  *smlen += horst_sigbytes;

  *addr.subtree_layer = 0;
  sign_leaf(root, N_LEVELS, sig.wots_signatures, smlen, tsk, address);

  zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  *smlen += mlen;

  return 0;
}



int crypto_sign_open(unsigned char *m,
                     unsigned long long *mlen,
                     const unsigned char *sm,
                     unsigned long long smlen,
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
               m_h);

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
                        const unsigned char *sk, const unsigned char *seed)
{
  *clen = 0;

  // =========================================
  // Generate initial leafidx from seed and sk
  // =========================================
  unsigned long long leafidx;

  unsigned char scratch[SK_RAND_SEED_BYTES + SEED_BYTES];
  memcpy(scratch, sk + CRYPTO_SECRETKEYBYTES - SK_RAND_SEED_BYTES,
         SK_RAND_SEED_BYTES);
  memcpy(scratch, seed, SEED_BYTES);
  unsigned long long rnd[8];
  crypto_hash_blake512((unsigned char*) rnd, scratch, SK_RAND_SEED_BYTES + SEED_BYTES);
  zerobytes(scratch, SK_RAND_SEED_BYTES + SEED_BYTES);

  // The lower 60 bit % (2^SUBTREE_HEIGHT) form the leafidx.
  // This comes down to picking a random subtree on the lowest level,
  // and picking the left-most leaf in that subtree
  leafidx = (rnd[0] & 0xfffffffffffffff);
  leafidx -= leafidx % (1<<SUBTREE_HEIGHT);

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
  treehash(context.level_0_hash, SUBTREE_HEIGHT, sk, address_bytes, public_seed);

  *clen += HASH_BYTES;


  // ==============================================================
  // Write the upper N_LEVELS - 1 WOTS signatures to the context
  // ==============================================================
  set_type(address_bytes, SPHINCS_ADDR);
  parent(SUBTREE_HEIGHT, address);
  sign_leaf(context.level_0_hash, N_LEVELS - 1, context.signatures, clen, sk, address_bytes);

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

int crypto_sign_open_update(unsigned char *m, unsigned long long *mlen,
                            const unsigned char* context, unsigned long long *clen,
                            const unsigned char* sig, unsigned long long smlen,
                            const unsigned char *pk)
{
  // ==============================================================
  // Construct message hash
  // ==============================================================

  // ==============================================================
  // Reconstruct leafidx
  // ==============================================================

  // ==============================================================
  // Verify horst signature
  // ==============================================================

  // ==============================================================
  // Verify WOTS signature
  // ==============================================================

  // ==============================================================
  // Restore root of lowest SPHINCS tree
  // ==============================================================

  // ==============================================================
  // Compare that root with the root in context
  // ==============================================================
  return 0;
}
