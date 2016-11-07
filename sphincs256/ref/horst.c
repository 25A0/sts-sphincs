#include "params.h"
#include "horst.h"
#include "hash.h"
#include "prg.h"
#include <stdint.h>
#include <stdio.h>
#include "hash_address.h"

static void hexdump_s(const unsigned char *data, int start, int len)
{
  int i;
  for(i = 0; i < len; i++) {
    if(i % 32 == 0) printf("\n%04d: ", i);
    printf("%02x", data[start + i]);
    if(i % 2) printf(" ");
  }
  printf("\n");
}

static void expand_seed(unsigned char outseeds[HORST_T*HORST_SKBYTES], const unsigned char inseed[SEED_BYTES])
{
  prg(outseeds, HORST_T*HORST_SKBYTES, inseed);
}

int horst_sign(unsigned char *sig, unsigned char pk[HASH_BYTES], unsigned long long *sigbytes, 
               const unsigned char *m, unsigned long long mlen, 
               const unsigned char seed[SEED_BYTES], 
               uint32_t addr[ADDR_SIZE],
               const unsigned char m_hash[MSGHASH_BYTES])
{
  unsigned char sk[HORST_T*HORST_SKBYTES];
  unsigned int idx;
  int i,j,k;
  int sigpos = 0;

  set_type(addr, HORST_ADDR);

  unsigned char tree[(2*HORST_T-1)*HASH_BYTES]; /* replace by something more memory-efficient? */

  expand_seed(sk, seed);

  // Build the whole tree and save it
#if HORST_SKBYTES != HASH_BYTES
#error "Need to have HORST_SKBYTES == HASH_BYTES"
#endif

  // Generate pk leaves
  for(i=0;i<HORST_T;i++) {
    set_horst_node(addr, i);
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
      set_horst_node(addr, idx++);
      hash_2n_n_addr(tree+(offset_out+j)*HASH_BYTES,
                     tree+(offset_in+2*j)*HASH_BYTES,
                     (const unsigned char*) addr);
    }
  }

#if HORST_K != (MSGHASH_BYTES/2)
#error "Need to have HORST_K == (MSGHASH_BYTES/2)"
#endif

  // First write 64 hashes from level 10 to the signature
  for(j=63*HASH_BYTES;j<127*HASH_BYTES;j++)
    sig[sigpos++] = tree[j];

  // Signature consists of HORST_K parts; each part of secret key and HORST_LOGT-4 auth-path hashes
  for(i=0;i<HORST_K;i++)
  {
    idx = m_hash[2*i] + (m_hash[2*i+1]<<8);

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
  
  *sigbytes = HORST_SIGBYTES;
  return 0;
}

int horst_verify(unsigned char *pk,
                 const unsigned char *sig,
                 const unsigned char *m,
                 unsigned long long mlen,
                 uint32_t addr[ADDR_SIZE],
                 const unsigned char m_hash[MSGHASH_BYTES])
{
  unsigned char buffer[32*HASH_BYTES];
  const unsigned char *level10;
  unsigned int idx;
  int i,j,k;

#if HORST_K != (MSGHASH_BYTES/2)
#error "Need to have HORST_K == (MSGHASH_BYTES/2)"
#endif

  level10 = sig;
  sig+=64*HASH_BYTES;

  set_type(addr, HORST_ADDR);

  for(i=0;i<HORST_K;i++)
  {
    idx = m_hash[2*i] + (m_hash[2*i+1]<<8);

#if HORST_SKBYTES != HASH_BYTES
#error "Need to have HORST_SKBYTES == HASH_BYTES"
#endif

    if(!(idx&1))
    {
      set_horst_node(addr, idx);
      hash_n_n_addr(buffer,
                    sig,
                    (const unsigned char*) addr);
      for(k=0;k<HASH_BYTES;k++)
        buffer[HASH_BYTES+k] = sig[HORST_SKBYTES+k];
    }
    else
    {
      set_horst_node(addr, idx);
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

      set_horst_node(addr, offset + idx);
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
    set_horst_node(addr, node_index(HORST_LOGT, HORST_LOGT-6, idx));
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
    set_horst_node(addr, idx++);
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   level10+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 11 to 12
  for(j=0;j<16;j++) {
    set_horst_node(addr, idx++);
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 12 to 13
  for(j=0;j<8;j++) {
    set_horst_node(addr, idx++);
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 13 to 14
  for(j=0;j<4;j++) {
    set_horst_node(addr, idx++);
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 14 to 15
  for(j=0;j<2;j++) {
    set_horst_node(addr, idx++);
    hash_2n_n_addr(buffer+j*HASH_BYTES,
                   buffer+2*j*HASH_BYTES,
                   (const unsigned char*) addr);
  }
  // Hash from level 15 to 16
  set_horst_node(addr, idx++);
  hash_2n_n_addr(pk,
                 buffer,
                 (const unsigned char*) addr);

  return 0;


fail:
  for(k=0;k<HASH_BYTES;k++)
    pk[k] = 0;
  return -1;
}

