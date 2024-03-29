#include "params.h"
#include "permute.h"

#include "crypto_hash_blake256.h"
#include "crypto_hash_blake512.h"

#include <stddef.h>

#include "hash_address.h"

int varlen_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  //SHA256(in,inlen,out);
  crypto_hash_blake256(out,in,inlen);
  return 0;
}

int msg_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  //SHA512(in,inlen,out);
  crypto_hash_blake512(out,in,inlen);
  return 0;
}


static const char *hashc = "expand 32-byte to 64-byte state!";

int hash_2n_n(unsigned char *out,const unsigned char *in)
{
#if HASH_BYTES != 32
#error "Current code only supports 32-byte hashes"
#endif

  unsigned char x[64];
  int i;
  for(i=0;i<32;i++)
  {
    x[i]    = in[i];
    x[i+32] = hashc[i];
  }
  chacha_permute(x,x);
  for(i=0;i<32;i++)
    x[i] = x[i] ^ in[i+32];
  chacha_permute(x,x);
  for(i=0;i<32;i++)
    out[i] = x[i];

  return 0;
}

int hash_2n_n_mask(unsigned char *out,const unsigned char *in, const unsigned char *mask)
{
  unsigned char buf[2*HASH_BYTES];
  int i;
  for(i=0;i<2*HASH_BYTES;i++)
    buf[i] = in[i] ^ mask[i];
  return hash_2n_n(out, buf);
}

int hash_n_n(unsigned char *out,const unsigned char *in)
{
#if HASH_BYTES != 32
#error "Current code only supports 32-byte hashes"
#endif

  unsigned char x[64];
  int i;

  for(i=0;i<32;i++)
  {
    x[i]    = in[i];
    x[i+32] = hashc[i];
  }
  chacha_permute(x,x);
  for(i=0;i<32;i++)
    out[i] = x[i];
  
  return 0;
}

int hash_n_n_mask(unsigned char *out,const unsigned char *in, const unsigned char *mask)
{
  unsigned char buf[HASH_BYTES];
  int i;
  for(i=0;i<HASH_BYTES;i++)
    buf[i] = in[i] ^ mask[i];
  return hash_n_n(out, buf);
}

int hash_n_n_addr(unsigned char *out,
                  const unsigned char *in,
                  const unsigned char *addr)
{
  unsigned char buf[HASH_BYTES + ADDR_BYTES];
  int i;
  for(i = 0; i < HASH_BYTES; i++)
    buf[i] = in[i];
  for(i = 0; i < ADDR_BYTES; i++)
    buf[HASH_BYTES + i] = addr[i];
  return varlen_hash(out, buf, HASH_BYTES + ADDR_BYTES);
}

int hash_2n_n_addr(unsigned char *out,
                   const unsigned char *in,
                   const unsigned char *addr)
{
  unsigned char buf[2*HASH_BYTES + ADDR_BYTES];
  int i;
  for(i = 0; i < 2*HASH_BYTES; i++)
    buf[i] = in[i];
  for(i = 0; i < ADDR_BYTES; i++)
    buf[2*HASH_BYTES + i] = addr[i];
  return varlen_hash(out, buf, 2*HASH_BYTES + ADDR_BYTES);
}

int hash_n_n_addr_seeded(unsigned char *out,
                         const unsigned char *in,
                         const unsigned char *addr,
                         const unsigned char *seed)
{
  unsigned char buf[HASH_BYTES + ADDR_BYTES + PUBLIC_SEED_BYTES];
  int i;
  for(i = 0; i < HASH_BYTES; i++)
    buf[i] = in[i];
  for(i = 0; i < ADDR_BYTES; i++)
    buf[HASH_BYTES + i] = addr[i];
  for(i = 0; i < PUBLIC_SEED_BYTES; i++)
    buf[HASH_BYTES + ADDR_BYTES + i] = seed[i];
  return varlen_hash(out, buf, HASH_BYTES + ADDR_BYTES + PUBLIC_SEED_BYTES);
}

int hash_2n_n_addr_seeded(unsigned char *out,
                          const unsigned char *in,
                          const unsigned char *addr,
                          const unsigned char *seed)
{
  unsigned char buf[2*HASH_BYTES + ADDR_BYTES + PUBLIC_SEED_BYTES];
  int i;
  for(i = 0; i < 2*HASH_BYTES; i++)
    buf[i] = in[i];
  for(i = 0; i < ADDR_BYTES; i++)
    buf[2*HASH_BYTES + i] = addr[i];
  for(i = 0; i < PUBLIC_SEED_BYTES; i++)
    buf[2*HASH_BYTES + ADDR_BYTES + i] = seed[i];
  return varlen_hash(out, buf, 2*HASH_BYTES + ADDR_BYTES + PUBLIC_SEED_BYTES);
}
