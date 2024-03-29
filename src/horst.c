#include "params.h"
#include "horst.h"
#include "hash.h"
#include "prg.h"
#include <stdint.h>
#include <stdio.h>
#include "hash_address.h"
#include <assert.h>

struct horst_config default_horst_config = {HORST_K, HORST_SIGBYTES};

static void expand_seed(unsigned char outseeds[HORST_T*HORST_SKBYTES],
                        const unsigned char inseed[SEED_BYTES])
{
  prg(outseeds, HORST_T*HORST_SKBYTES, inseed);
}

int horst_sign(unsigned char *sig, unsigned char pk[HASH_BYTES],
               unsigned long long *sigbytes,
               const unsigned char seed[SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               const unsigned char* m, unsigned int mlen)
{
  return horst_sign_conf(sig, pk, sigbytes, seed, addr, m, mlen, default_horst_config);
}

int horst_sign_conf(unsigned char *sig, unsigned char pk[HASH_BYTES],
                    unsigned long long *sigbytes,
                    const unsigned char seed[SEED_BYTES],
                    unsigned char addr[ADDR_BYTES],
                    const unsigned char* m, unsigned int mlen,
                    struct horst_config config)
{
  unsigned char sk[HORST_T*HORST_SKBYTES];
  unsigned int idx;
  int i,j,k;
  int sigpos = 0;

  // Make sure that the configuration fits the declared message length
  assert(mlen * 8 == HORST_LOGT * config.horst_k);

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, HORST_ADDR);

  unsigned char tree[(2*HORST_T-1)*HASH_BYTES]; /* replace by something more memory-efficient? */

  expand_seed(sk, seed);

  // Build the whole tree and save it
#if HORST_SKBYTES != HASH_BYTES
#error "Need to have HORST_SKBYTES == HASH_BYTES"
#endif

  // Generate pk leaves
  for(i=0;i<HORST_T;i++) {
    *address.horst_node = i;
    hash_n_n_addr(tree+(HORST_T-1+i)*HASH_BYTES,
                  sk+i*HORST_SKBYTES,
                  (const unsigned char*) addr);
  }


  unsigned long long offset_in, offset_out;
  idx = node_index(HORST_LOGT, 1, 0);
  for(i=0;i<HORST_LOGT;i++)
  {
    offset_in = (1<<(HORST_LOGT-i))-1;
    offset_out = (1<<(HORST_LOGT-i-1))-1;
    for(j=0;j < (1<<(HORST_LOGT-i-1));j++) {
      *address.horst_node = idx++;
      hash_2n_n_addr(tree+(offset_out+j)*HASH_BYTES,
                     tree+(offset_in+2*j)*HASH_BYTES,
                     (const unsigned char*) addr);
    }
  }

  assert(HORST_LOGT == 16);

  // First write 64 hashes from level 10 to the signature
  for(j=63*HASH_BYTES;j<127*HASH_BYTES;j++)
    sig[sigpos++] = tree[j];

  // Signature consists of horst_k parts; each part of secret key and
  // horst_logt-4 auth-path hashes
  for(i=0;i<config.horst_k;i++)
  {
    idx = m[2*i] + (m[2*i+1]<<8);

    for(k=0;k<HORST_SKBYTES;k++)
      sig[sigpos++] = sk[idx*HORST_SKBYTES+k];

    idx += (HORST_T-1);
    for(j=0;j<HORST_LOGT-6;j++)
    {
      idx = (idx&1)?idx+1:idx-1; // neighbor node
      for(k=0;k<HASH_BYTES;k++)
        sig[sigpos++] = tree[idx*HASH_BYTES+k];
      idx = (idx-1)/2; // parent node
    }
  }

  for(i=0;i<HASH_BYTES;i++)
    pk[i] = tree[i];

  *sigbytes = config.horst_sigbytes;
  return 0;
}

int horst_verify(unsigned char *pk,
                 const unsigned char *sig,
                 unsigned char addr[ADDR_BYTES],
                 const unsigned char* m, unsigned int mlen)
{
  return horst_verify_conf(pk, sig, addr, m, mlen, default_horst_config);
}

int horst_verify_conf(unsigned char *pk,
                      const unsigned char *sig,
                      unsigned char addr[ADDR_BYTES],
                      const unsigned char* m, unsigned int mlen,
                      struct horst_config config)
{
  unsigned char buffer[32*HASH_BYTES];
  const unsigned char *level10;
  unsigned int idx;
  int i,j,k;

  assert(mlen * 8 == HORST_LOGT * config.horst_k);

  level10 = sig;
  sig+=64*HASH_BYTES;

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, HORST_ADDR);

  for(i=0;i<config.horst_k;i++)
  {
    idx = m[2*i] + (m[2*i+1]<<8);

#if HORST_SKBYTES != HASH_BYTES
#error "Need to have HORST_SKBYTES == HASH_BYTES"
#endif

    if(!(idx&1))
    {
      *address.horst_node = idx;
      hash_n_n_addr(buffer,
                    sig,
                    (const unsigned char*) addr);
      for(k=0;k<HASH_BYTES;k++)
        buffer[HASH_BYTES+k] = sig[HORST_SKBYTES+k];
    }
    else
    {
      *address.horst_node = idx;
      hash_n_n_addr(buffer + HASH_BYTES,
                    sig,
                    (const unsigned char*) addr);
      for(k=0;k<HASH_BYTES;k++)
        buffer[k] = sig[HORST_SKBYTES+k];
    }
    sig += HORST_SKBYTES+HASH_BYTES;

    int offset = HORST_T;
    for(j=1;j<HORST_LOGT-6;j++)
    {
      idx = idx>>1; // parent node

      *address.horst_node = offset + idx;
      if(!(idx&1))
      {
        hash_2n_n_addr(buffer,
                       buffer,
                       (const unsigned char*) addr);
        for(k=0;k<HASH_BYTES;k++)
          buffer[HASH_BYTES+k] = sig[k];
      }
      else
      {
        hash_2n_n_addr(buffer + HASH_BYTES,
                       buffer,
                       (const unsigned char*) addr);
        for(k=0;k<HASH_BYTES;k++)
          buffer[k] = sig[k];
      }
      sig += HASH_BYTES;

      offset += 1<<(HORST_LOGT - j);
    }

    idx = idx>>1; // parent node
    *address.horst_node = node_index(HORST_LOGT, HORST_LOGT-6, idx);
    hash_2n_n_addr(buffer,
                   buffer,
                   (const unsigned char*) addr);

    for(k=0;k<HASH_BYTES;k++)
      if(level10[idx*HASH_BYTES+k] != buffer[k]) 
        goto fail;
  }

  // We compute hashes to form nodes on the 11th layer
  idx = node_index(HORST_LOGT, HORST_LOGT - 6 + 1, 0);
  // Compute root from level10
  for(j=0;j<32;j++) {
    *address.horst_node = idx++;
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   level10+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 11 to 12
  for(j=0;j<16;j++) {
    *address.horst_node = idx++;
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 12 to 13
  for(j=0;j<8;j++) {
    *address.horst_node = idx++;
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 13 to 14
  for(j=0;j<4;j++) {
    *address.horst_node = idx++;
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 14 to 15
  for(j=0;j<2;j++) {
    *address.horst_node = idx++;
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 15 to 16
  *address.horst_node = idx++;
  hash_2n_n_addr(pk,
                 buffer,
                 (const unsigned char*) addr);

  return 0;


fail:
  for(k=0;k<HASH_BYTES;k++)
    pk[k] = 0;
  return -1;
}

