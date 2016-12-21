#include "crypto_sign.h"
#include <stdlib.h>
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
  set_sphincs_subtree_layer(address, N_LEVELS - 1);
  set_sphincs_subtree(address, 0);
  set_sphincs_subtree_node(address, 0);

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

static int sign_leaf(const unsigned char* leaf, int start_height,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *sk,
                     unsigned char *address)
{
  int i;
  unsigned char root[HASH_BYTES];
  memcpy(root, leaf, HASH_BYTES);
  unsigned char seed[SEED_BYTES];
  const unsigned char* public_seed = get_public_seed_from_sk(sk);
  for(i=start_height;i<N_LEVELS;i++)
  {
    set_sphincs_subtree_layer(address, i);
    // a.level = i;

    get_seed(seed, sk, address); //XXX: Don't use the same address as for horst_sign here!
    wots_sign(sm, root, seed, public_seed, address);
    sm += WOTS_SIGBYTES;
    *smlen += WOTS_SIGBYTES;

    compute_authpath_wots(root,sm,address,sk,SUBTREE_HEIGHT, public_seed);
    sm += SUBTREE_HEIGHT*HASH_BYTES;
    *smlen += SUBTREE_HEIGHT*HASH_BYTES;

    set_sphincs_subtree_node(address, get_sphincs_subtree_node(address) & ((1<<SUBTREE_HEIGHT)-1));
    //a.subleaf = a.subtree & ((1<<SUBTREE_HEIGHT)-1);
    set_sphincs_subtree(address, get_sphincs_subtree(address) >> SUBTREE_HEIGHT);
    //a.subtree >>= SUBTREE_HEIGHT;
  }
  return 0;
}

static int verify_leaf(unsigned char *root, int start_height,
                       unsigned char *sigp, unsigned long long smlen,
                       const unsigned char *pk,
                       unsigned char *address)
{
  unsigned char wots_pk[WOTS_L*HASH_BYTES];
  unsigned char pkhash[HASH_BYTES];
  const unsigned char* public_seed = get_public_seed_from_pk(pk);
  int i;
  for(i=start_height;i<N_LEVELS;i++)
  {
    set_sphincs_subtree_layer(address, i);
    wots_verify(wots_pk, sigp, root, public_seed, address);

    sigp += WOTS_SIGBYTES;
    smlen -= WOTS_SIGBYTES;

    l_tree(pkhash, wots_pk, address, public_seed);
    // validate_authpath(root, pkhash, leafidx & 0x1f, sigp, tpk, SUBTREE_HEIGHT);
    validate_authpath(root, pkhash, address, public_seed, sigp, SUBTREE_HEIGHT);

    // leafidx >>= SUBTREE_HEIGHT;
    set_sphincs_subtree_node(address, get_sphincs_subtree_node(address) & ((1<<SUBTREE_HEIGHT)-1));
    set_sphincs_subtree(address, get_sphincs_subtree(address) >> SUBTREE_HEIGHT);

    sigp += SUBTREE_HEIGHT*HASH_BYTES;
    smlen -= SUBTREE_HEIGHT*HASH_BYTES;
  }
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
    set_sphincs_subtree_layer(address, N_LEVELS - 1);
    set_sphincs_subtree(address, 0);
    set_sphincs_subtree_node(address, 0);

    pk = scratch + MESSAGE_HASH_SEED_BYTES;

    treehash(pk, SUBTREE_HEIGHT, tsk, address, public_seed);

    // Include public seed
    memcpy(pk + HASH_BYTES, get_public_seed_from_sk(sk), PUBLIC_SEED_BYTES);

    // message already on the right spot
    msg_hash(m_h, scratch, mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);
  }

  set_sphincs_subtree_layer(address, N_LEVELS);
  set_sphincs_subtree(address, leafidx >> SUBTREE_HEIGHT);
  set_sphincs_subtree_node(address, leafidx & ((1<<SUBTREE_HEIGHT)-1));

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

  sign_leaf(root, 0, sm, smlen, tsk, address);

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
  set_sphincs_subtree_layer(address, N_LEVELS);
  set_sphincs_subtree(address, leafidx >> SUBTREE_HEIGHT);
  set_sphincs_subtree_node(address, leafidx & ((1<<SUBTREE_HEIGHT)-1));

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

  verify_leaf(root, 0, sigp, smlen, pk, address);

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
  return 0;

}

int crypto_sign_full(unsigned char *m, unsigned long long mlen,
                     unsigned char *context, unsigned long long *clen,
                     unsigned char *sig, unsigned long long *slen,
                     const unsigned char *sk)
{
  return 0;

}

int crypto_sign_update(unsigned char *m, unsigned long long mlen,
                       unsigned char *context, unsigned long long *clen,
                       unsigned char *sig, unsigned long long *slen,
                       const unsigned char *sk)
{
  return 0;

}

int crypto_sign_open_full(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
  return 0;

}

int crypto_sign_open_update(unsigned char *m, unsigned long long *mlen,
                            const unsigned char* context, unsigned long long *clen,
                            const unsigned char* sig, unsigned long long smlen,
                            const unsigned char *pk)
{
  return 0;

}
