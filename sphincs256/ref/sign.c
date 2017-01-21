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

static void hexdump_s(unsigned char *data, int start, int len)
{
  int i;
  for(i = 0; i < len; i++) {
    if(i % 32 == 0) printf("\n%04d: ", i);
    printf("%02x", data[start + i]);
    if(i % 2) printf(" ");
  }
  printf("\n");
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

  for(i=0; i<MESSAGE_HASH_SEED_BYTES; i++)
    sm[i] = R[i];

  sm += MESSAGE_HASH_SEED_BYTES;
  *smlen += MESSAGE_HASH_SEED_BYTES;

  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    sm[i] = (leafidx >> 8*i) & 0xff;

  sm += (TOTALTREE_HEIGHT+7)/8;
  *smlen += (TOTALTREE_HEIGHT+7)/8;

  get_seed(seed, tsk, address);
  horst_sign(sm, root, &horst_sigbytes, m, mlen, seed, address, m_h);

  sm += horst_sigbytes;
  *smlen += horst_sigbytes;

  *addr.subtree_layer = 0;
  sign_leaf(root, N_LEVELS, sm, smlen, tsk, address);

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
  unsigned char sig[CRYPTO_BYTES];
  unsigned char *sigp;
  unsigned char tpk[CRYPTO_PUBLICKEYBYTES];

  if(smlen < CRYPTO_BYTES)
    return -1;

  unsigned char m_h[MSGHASH_BYTES];

  for(i=0;i<CRYPTO_PUBLICKEYBYTES;i++)
    tpk[i] = pk[i];

  // construct message hash
  {
    unsigned char R[MESSAGE_HASH_SEED_BYTES];

    for(i=0; i<MESSAGE_HASH_SEED_BYTES; i++)
      R[i] = sm[i];

    // Message length
    int len = smlen - CRYPTO_BYTES;

    unsigned char *scratch = m;

    memcpy(sig, sm, CRYPTO_BYTES);

    memcpy(scratch + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES, sm + CRYPTO_BYTES, len);

    // cpy R
    memcpy(scratch, R, MESSAGE_HASH_SEED_BYTES);

    // cpy pub key
    memcpy(scratch + MESSAGE_HASH_SEED_BYTES, tpk, CRYPTO_PUBLICKEYBYTES);

    msg_hash(m_h, scratch, len + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);

  }
  sigp = &sig[0];

  sigp += MESSAGE_HASH_SEED_BYTES;
  smlen -= MESSAGE_HASH_SEED_BYTES;


  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    leafidx ^= (((unsigned long long)sigp[i]) << 8*i);

  unsigned char address[ADDR_BYTES];
  struct hash_addr addr = init_hash_addr(address);
  *addr.subtree_layer = N_LEVELS;
  *addr.subtree_address = leafidx >> SUBTREE_HEIGHT;
  *addr.subtree_node = leafidx & ((1<<SUBTREE_HEIGHT)-1);

  horst_verify(root,
               sigp+(TOTALTREE_HEIGHT+7)/8,
               sigp+CRYPTO_BYTES-MESSAGE_HASH_SEED_BYTES,
               smlen-CRYPTO_BYTES-MESSAGE_HASH_SEED_BYTES,
               address,
               m_h);

  sigp += (TOTALTREE_HEIGHT+7)/8;
  smlen -= (TOTALTREE_HEIGHT+7)/8;
  
  sigp += HORST_SIGBYTES;
  smlen -= HORST_SIGBYTES;

  *addr.subtree_layer = 0;
  verify_leaf(root, N_LEVELS, sigp, smlen, pk, address);

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
static int increment_context(unsigned char *context) {
  return 0;
}

int crypto_context_init(unsigned char *context, unsigned long long *clen,
                        const unsigned char *sk, const unsigned char *seed)
{
  int i;
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

  // ==============================================================
  // Write the current leafidx to the context
  // ==============================================================
  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    context[i] = (leafidx >> 8*i) & 0xff;

  context += (TOTALTREE_HEIGHT+7)/8;
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

  unsigned char* subtree_root = context;

  context += HASH_BYTES;
  *clen += HASH_BYTES;


  // ==============================================================
  // Write the MESSAGE_HASH_SEED to the context
  // ==============================================================
  memcpy(context, &rnd[2], MESSAGE_HASH_SEED_BYTES);
  context += MESSAGE_HASH_SEED_BYTES;
  *clen += MESSAGE_HASH_SEED_BYTES;

  // ==============================================================
  // Write the upper N_LEVELS - 1 WOTS signatures to the context
  // ==============================================================
  set_type(address_bytes, SPHINCS_ADDR);
  *address.subtree_layer = 1;
  *address.subtree_node = *address.subtree_node >> SUBTREE_HEIGHT;
  *address.subtree_address = *address.subtree_address >> SUBTREE_HEIGHT;
  sign_leaf(subtree_root, N_LEVELS - 1, context, clen, sk, address_bytes);

  return 0;
}

int crypto_sign_full(unsigned char *m, unsigned long long mlen,
                     unsigned char *context, unsigned long long *clen,
                     unsigned char *sig, unsigned long long *slen,
                     const unsigned char *sk)
{
  unsigned char* sigp = sig;
  *slen = 0;

  // ==============================================================
  // Copy the message hash seed to the beginning of the signature
  // ==============================================================
  memcpy(sigp, context + (TOTALTREE_HEIGHT+7)/8 + HASH_BYTES,
         MESSAGE_HASH_SEED_BYTES);

  sigp += MESSAGE_HASH_SEED_BYTES;
  *slen += MESSAGE_HASH_SEED_BYTES;

  // ==============================================================
  // Do whatever we do when we update a signature
  // ==============================================================
  unsigned long long uslen = 0;
  crypto_sign_update(m, mlen, context, clen, sigp, &uslen, sk);
  sigp += uslen;
  *slen += uslen;

  // ==============================================================
  // Copy remaining signatures from context
  // ==============================================================

  // Copy the WOTS signatures and auth paths for the upper N_LEVELS - 1
  // levels to the signature.
  // We assume that the sig pointer has been shifted forwards while
  // crypto_sign_update has written to it.
  memcpy(sigp, context + (TOTALTREE_HEIGHT+7)/8 + HASH_BYTES + MESSAGE_HASH_SEED_BYTES,
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
                       unsigned char *context, unsigned long long *clen,
                       unsigned char *sig, unsigned long long *slen,
                       const unsigned char *sk)
{
  *slen = 0;
  int i;

  unsigned char tsk[CRYPTO_SECRETKEYBYTES];
  for(i=0;i<CRYPTO_SECRETKEYBYTES;i++)
    tsk[i] = sk[i];

  // ==============================================================
  // Update leafidx. Return if we're out of leaves
  // ==============================================================
  int res = increment_context(context);
  if(res != 0) return res;

  // Read leafidx from updated context
  unsigned long long leafidx = 0;
  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    leafidx ^= (((unsigned long long)context[i]) << 8*i);

  // Write used leafidx to signature
  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    sig[i] = (leafidx >> 8*i) & 0xff;

  sig += (TOTALTREE_HEIGHT+7)/8;
  *slen += (TOTALTREE_HEIGHT+7)/8;

  // ==============================================================
  // Hash message
  // ==============================================================
  unsigned char scratch[mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES];
  unsigned char* sp = scratch;
  memcpy(sp, context + (TOTALTREE_HEIGHT+7)/8 + HASH_BYTES,
         MESSAGE_HASH_SEED_BYTES);
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
  horst_sign(sig, root, &horst_sigbytes, m, mlen, seed, address_bytes, m_h);

  sig += horst_sigbytes;
  *slen += horst_sigbytes;

  // ==============================================================
  // Create WOTS signature for lvl 0
  // ==============================================================
  *address.subtree_layer = 0;
  sign_leaf(root, 1, sig, slen, tsk, address_bytes);

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
