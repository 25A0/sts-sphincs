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



/*
 * Format pk: [|N_MASKS*HASH_BYTES| Bitmasks || root]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  leafaddr a;

  randombytes(sk,CRYPTO_SECRETKEYBYTES);
  memcpy(pk,sk+SEED_BYTES,N_MASKS*HASH_BYTES);

  // Initialization of top-subtree address
  a.level   = N_LEVELS - 1;
  a.subtree = 0;
  a.subleaf = 0;

  // Construct top subtree
  treehash(pk+(N_MASKS*HASH_BYTES), SUBTREE_HEIGHT, sk, &a, pk);
  return 0;
}


int crypto_sign(unsigned char *sm,unsigned long long *smlen, const unsigned char *m,unsigned long long mlen, const unsigned char *sk)
{
  leafaddr a;
  unsigned long long i;
  unsigned long long leafidx;
  unsigned char R[MESSAGE_HASH_SEED_BYTES];
  unsigned char m_h[MSGHASH_BYTES];
  unsigned long long rnd[8];
  unsigned long long horst_sigbytes;
  unsigned char root[HASH_BYTES];
  unsigned char seed[SEED_BYTES];
  unsigned char masks[N_MASKS*HASH_BYTES];
  unsigned char *pk;
  unsigned char tsk[CRYPTO_SECRETKEYBYTES];

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

    // construct and cpy pk
    leafaddr a;
    a.level = N_LEVELS - 1;
    a.subtree = 0;
    a.subleaf=0;

    pk = scratch + MESSAGE_HASH_SEED_BYTES;

    memcpy(pk, tsk+SEED_BYTES, N_MASKS*HASH_BYTES);

    treehash(pk+(N_MASKS*HASH_BYTES), SUBTREE_HEIGHT, tsk, &a, pk);

    // message already on the right spot

    msg_hash(m_h, scratch, mlen + MESSAGE_HASH_SEED_BYTES + CRYPTO_PUBLICKEYBYTES);
  }

  a.level   = N_LEVELS; // Use unique value $d$ for HORST address.
  a.subleaf = leafidx & ((1<<SUBTREE_HEIGHT)-1);
  a.subtree = leafidx >> SUBTREE_HEIGHT;

  *smlen = 0;

  for(i=0; i<MESSAGE_HASH_SEED_BYTES; i++)
    sm[i] = R[i];

  sm += MESSAGE_HASH_SEED_BYTES;
  *smlen += MESSAGE_HASH_SEED_BYTES;

  memcpy(masks, tsk+SEED_BYTES,N_MASKS*HASH_BYTES);
  for(i=0;i<(TOTALTREE_HEIGHT+7)/8;i++)
    sm[i] = (leafidx >> 8*i) & 0xff;

  sm += (TOTALTREE_HEIGHT+7)/8;
  *smlen += (TOTALTREE_HEIGHT+7)/8;

  uint32_t hash_addr[ADDR_SIZE];
  for(i = 0; i < ADDR_SIZE; i++)
    hash_addr[i] = 0;

  char public_seed[PUBLIC_SEED_BYTES];
  for(i = 0; i < PUBLIC_SEED_BYTES; i++)
    public_seed[i] = 0;


  get_seed(seed, tsk, &a);
  horst_sign(sm, root, &horst_sigbytes, m, mlen, seed, hash_addr, m_h);

  sm += horst_sigbytes;
  *smlen += horst_sigbytes;
  
  for(i=0;i<N_LEVELS;i++)
  {
    a.level = i;

    get_seed(seed, tsk, &a); //XXX: Don't use the same address as for horst_sign here!
    wots_sign(sm, root, seed, public_seed, hash_addr);
    sm += WOTS_SIGBYTES;
    *smlen += WOTS_SIGBYTES;

    compute_authpath_wots(root,sm,&a,tsk,masks,SUBTREE_HEIGHT);
    sm += SUBTREE_HEIGHT*HASH_BYTES;
    *smlen += SUBTREE_HEIGHT*HASH_BYTES;
    
    a.subleaf = a.subtree & ((1<<SUBTREE_HEIGHT)-1);
    a.subtree >>= SUBTREE_HEIGHT;
  }

  zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  *smlen += mlen;

  return 0;
}



int crypto_sign_open(unsigned char *m,unsigned long long *mlen, const unsigned char *sm,unsigned long long smlen, const unsigned char *pk)
{
  unsigned long long i;
  unsigned long long leafidx=0;
  unsigned char wots_pk[WOTS_L*HASH_BYTES];
  unsigned char pkhash[HASH_BYTES];
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

  uint32_t hash_addr[ADDR_SIZE];
  for(i = 0; i < ADDR_SIZE; i++)
    hash_addr[i] = 0;

  char public_seed[PUBLIC_SEED_BYTES];
  for(i = 0; i < PUBLIC_SEED_BYTES; i++)
    public_seed[i] = 0;


  horst_verify(root,
               sigp+(TOTALTREE_HEIGHT+7)/8,
               sigp+CRYPTO_BYTES-MESSAGE_HASH_SEED_BYTES,
               smlen-CRYPTO_BYTES-MESSAGE_HASH_SEED_BYTES,
               hash_addr,
               m_h);

  sigp += (TOTALTREE_HEIGHT+7)/8;
  smlen -= (TOTALTREE_HEIGHT+7)/8;
  
  sigp += HORST_SIGBYTES;
  smlen -= HORST_SIGBYTES;

  for(i=0;i<N_LEVELS;i++)
  {
    wots_verify(wots_pk, sigp, root, public_seed, hash_addr);

    sigp += WOTS_SIGBYTES;
    smlen -= WOTS_SIGBYTES;

    l_tree(pkhash, wots_pk,tpk);
    validate_authpath(root, pkhash, leafidx & 0x1f, sigp, tpk, SUBTREE_HEIGHT);  
    leafidx >>= 5;

    sigp += SUBTREE_HEIGHT*HASH_BYTES;
    smlen -= SUBTREE_HEIGHT*HASH_BYTES;
  }

  for(i=0;i<HASH_BYTES;i++)
    if(root[i] != tpk[i+N_MASKS*HASH_BYTES])
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

