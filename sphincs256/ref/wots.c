#include "params.h"
#include "prg.h"
#include "hash.h"
#include "hash_address.h"

static void expand_seed(unsigned char out[WOTS_L*HASH_BYTES],
                        const unsigned char sk[SEED_BYTES],
                        unsigned char addr[ADDR_BYTES])
{
  int i;
  for(i = 0; i < WOTS_L; i++) {
    set_wots_ots_index(addr, i);
    set_wots_chain_index(addr, 0);
    hash_n_n_addr(out + i * HASH_BYTES, sk, addr);
  }
}


/*
 * XMSS-T chaining function
 * addr uniquely identifies this chain
 * chainlen is the number of iterations that should be performed
 */
void gen_chain(unsigned char out[HASH_BYTES],
               const unsigned char in[HASH_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               int chainlen,
               int start_link)
{
  if(chainlen) {
    int n;

    // call gen_chain recursively for i - 1
    gen_chain(out, in, seed, addr, chainlen - 1, start_link);
    start_link += chainlen - 1;

    // buffer holding k_ij and r_ij, in this order
    unsigned char kr[2 * HASH_BYTES];

    // Note that chainlen will always be > 0
    set_wots_chain_index(addr, 2*start_link);
    hash_n_n_addr(kr, seed, (unsigned char*) addr);

    set_wots_chain_index(addr, 2*start_link + 1);
    hash_n_n_addr(kr + HASH_BYTES, seed, (unsigned char*) addr);

    for (n = 0; n < HASH_BYTES; ++n) {
      // Offset so that out is XORed with r_ij
      kr[n + HASH_BYTES] ^= out[n];
    }

    hash_2n_n(out, kr);

  } else {
    int n;
    for (n = 0; n < HASH_BYTES; n++)
    {
      out[n] = in[n];
    }
  }
}


void wots_pkgen(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                unsigned char addr[ADDR_BYTES])
{
  int i;
  set_type(addr, WOTS_ADDR);
  expand_seed(pk, sk, addr);
  for(i=0;i<WOTS_L;i++) {
    set_wots_ots_index(addr, i);
    gen_chain(pk+i*HASH_BYTES, pk+i*HASH_BYTES, seed, addr, WOTS_W-1, 0);
  }
}


void wots_sign(unsigned char sig[WOTS_L*HASH_BYTES],
               const unsigned char msg[HASH_BYTES],
               const unsigned char sk[SEED_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES])
{
  int basew[WOTS_L],i,c=0;

#if WOTS_W == 16
  for(i=0;i<WOTS_L1;i+=2)
  {
    basew[i]   = msg[i/2] & 0xf;
    basew[i+1] = msg[i/2] >> 4;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
  }

  for( ;i<WOTS_L;i++)
  {
    basew[i] = c & 0xf;
    c >>= 4;
  }

  set_type(addr, WOTS_ADDR);
  expand_seed(sig, sk, addr);
  for(i=0;i<WOTS_L;i++) {
    set_wots_ots_index(addr, i);
    gen_chain(sig+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, basew[i], 0);
  }

#elif WOTS_W == 4
  for(i=0;i<WOTS_L1;i+=4)
  {
    basew[i]   = msg[i/4] & 0x3;
    basew[i+1] = (msg[i/4] >> 2) & 0x3;
    basew[i+2] = (msg[i/4] >> 4) & 0x3;
    basew[i+3] = (msg[i/4] >> 6) & 0x3;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
    c += WOTS_W - 1 - basew[i+2];
    c += WOTS_W - 1 - basew[i+3];
  }

  for( ;i<WOTS_L;i++)
  {
    basew[i] = c & 0x3;
    c >>= 2;
  }

  set_type(addr, WOTS_ADDR);
  expand_seed(sig, sk, addr);
  for(i=0;i<WOTS_L;i++) {
    set_wots_ots_index(addr, i);
    gen_chain(sig+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, basew[i], 0);
  }

#else
#error "not yet implemented"
#endif
}

void wots_verify(unsigned char pk[WOTS_L*HASH_BYTES],
                 const unsigned char sig[WOTS_L*HASH_BYTES],
                 const unsigned char msg[HASH_BYTES],
                 const unsigned char seed[PUBLIC_SEED_BYTES],
                 unsigned char addr[ADDR_BYTES])
{
  int basew[WOTS_L],i,c=0;

#if WOTS_W == 16
  for(i=0;i<WOTS_L1;i+=2)
  {
    basew[i]   = msg[i/2] & 0xf;
    basew[i+1] = msg[i/2] >> 4;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
  }

  for( ;i<WOTS_L;i++)
  {
    basew[i] = c & 0xf;
    c >>= 4;
  }

  set_type(addr, WOTS_ADDR);
  for(i=0;i<WOTS_L;i++) {
    set_wots_ots_index(addr, i);
    gen_chain(pk+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, WOTS_W-1-basew[i], basew[i]);
  }

#elif WOTS_W == 4
  for(i=0;i<WOTS_L1;i+=4)
  {
    basew[i]   = msg[i/4] & 0x3;
    basew[i+1] = (msg[i/4] >> 2) & 0x3;
    basew[i+2] = (msg[i/4] >> 4) & 0x3;
    basew[i+3] = (msg[i/4] >> 6) & 0x3;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
    c += WOTS_W - 1 - basew[i+2];
    c += WOTS_W - 1 - basew[i+3];
  }

  for( ;i<WOTS_L;i++)
  {
    basew[i] = c & 0x3;
    c >>= 2;
  }

  set_type(addr, WOTS_ADDR);
  for(i=0;i<WOTS_L;i++) {
    set_wots_ots_index(addr, i);
    gen_chain(pk+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, WOTS_W-1-basew[i], basew[i]);
  }

#else
#error "not yet implemented"
#endif
}
