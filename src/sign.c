#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "sign.h"
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

#define BIGINT_BYTES ((TOTALTREE_HEIGHT-SUBTREE_HEIGHT+7)/8)

#if (TOTALTREE_HEIGHT-SUBTREE_HEIGHT) > 64
#error "TOTALTREE_HEIGHT-SUBTREE_HEIGHT must be at most 64" 
#endif

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

// Since the code should ideally work across systems with different endianness,
// this function defines unambiguously how an ull is serialized.
inline void write_ull(unsigned char* buf, const unsigned long long ull,
                      const unsigned int bytes) {
  int i;
  for(i=0;i<bytes;i++)
    buf[i] = (ull >> 8*i) & 0xff;
}

inline unsigned long long
read_ull(unsigned char* buf, const unsigned int bytes) {
  unsigned long long res = 0;
  int i;
  for(i=0;i<bytes;i++)
    res |= (((unsigned long long)buf[i]) << 8*i);
  return res;
}

inline const unsigned char* get_public_seed_from_pk(const unsigned char* pk) {
  return pk + HASH_BYTES;
}

inline const unsigned char* get_public_seed_from_sk(const unsigned char* sk) {
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
  horst_sign(sig.horst_signature, root, &horst_sigbytes, seed, address,
             m_h, MSGHASH_BYTES);

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

int get_system_entropy(void* buf, unsigned int length) {
    // TODO: ideally we should use getentropy from sys/random.h if it's
    // available.
    int file = open("/dev/urandom", O_RDONLY);
    int read_bytes = read(file, buf, length);
    close(file);
    if(read_bytes < length) return -1;
    else return 0;
}
