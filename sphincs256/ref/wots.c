#include "params.h"
#include "prg.h"
#include "hash.h"
#include "hash_address.h"
#include "assert.h"
#include "wots.h"

// A struct containing the default configuration
const struct wots_config default_wots_config = {WOTS_L, WOTS_L1, WOTS_LOG_L,
                                                WOTS_SIGBYTES};

static void expand_seed(unsigned char out[WOTS_L*HASH_BYTES],
                        const unsigned char sk[SEED_BYTES],
                        unsigned char addr[ADDR_BYTES],
                        struct wots_config config)
{
  int i;
  struct hash_addr address = init_hash_addr(addr);
  for(i = 0; i < config.wots_l; i++) {
    *address.wots_ots_index = i;
    *address.wots_ots_position = 0;
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
  struct hash_addr address = init_hash_addr(addr);
  int n;
  for (n = 0; n < HASH_BYTES; n++)
  {
    out[n] = in[n];
  }
  // buffer holding k_ij and r_ij, in this order
  unsigned char kr[2 * HASH_BYTES];
  assert(chainlen >= 0);
  assert(start_link >= 0);

  int link;
  for(link = 0; link < chainlen; link++) {
    // Note that chainlen will always be > 0
    *address.wots_ots_index = 2*(start_link + link);
    hash_n_n_addr(kr, seed, (unsigned char*) addr);

    *address.wots_ots_index = 2*(start_link + link) + 1;
    hash_n_n_addr(kr + HASH_BYTES, seed, (unsigned char*) addr);

    for (n = 0; n < HASH_BYTES; ++n) {
      // Offset so that out is XORed with r_ij
      kr[n + HASH_BYTES] ^= out[n];
    }

    hash_2n_n(out, kr);
  }

}


void wots_pkgen(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                unsigned char addr[ADDR_BYTES])
{
  wots_pkgen_conf(pk, sk, seed, addr, default_wots_config);
}

void wots_pkgen_conf(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                unsigned char addr[ADDR_BYTES],
                struct wots_config config)
{
  int i;
  set_type(addr, WOTS_ADDR);
  expand_seed(pk, sk, addr, config);
  struct hash_addr address = init_hash_addr(addr);
  for(i = 0; i < config.wots_l; i++) {
    *address.wots_ots_index = i;
    gen_chain(pk+i*HASH_BYTES, pk+i*HASH_BYTES, seed, addr, WOTS_W-1, 0);
  }
}


void wots_sign(unsigned char sig[WOTS_L*HASH_BYTES],
               const unsigned char msg[HASH_BYTES],
               const unsigned char sk[SEED_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES])
{
  wots_sign_conf(sig, msg, sk, seed, addr, default_wots_config);
}

void wots_sign_conf(unsigned char sig[WOTS_L*HASH_BYTES],
                    const unsigned char msg[HASH_BYTES],
                    const unsigned char sk[SEED_BYTES],
                    const unsigned char seed[PUBLIC_SEED_BYTES],
                    unsigned char addr[ADDR_BYTES],
                    struct wots_config config)
{
  int basew[config.wots_l],i,c=0;

#if WOTS_W == 16
  for(i=0;i<config.wots_l1;i+=2)
  {
    basew[i]   = msg[i/2] & 0xf;
    basew[i+1] = msg[i/2] >> 4;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
  }

  for( ;i<config.wots_l;i++)
  {
    basew[i] = c & 0xf;
    c >>= 4;
  }

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, WOTS_ADDR);
  expand_seed(sig, sk, addr, config);
  for(i=0;i<config.wots_l;i++) {
    *address.wots_ots_index = i;
    gen_chain(sig+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, basew[i], 0);
  }

#elif WOTS_W == 4
  for(i=0;i<config.wots_l1;i+=4)
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

  for( ;i<config.wots_l;i++)
  {
    basew[i] = c & 0x3;
    c >>= 2;
  }

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, WOTS_ADDR);
  expand_seed(sig, sk, addr);
  for(i=0;i<config.wots_l;i++) {
    *address.wots_ots_index = i;
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
  wots_verify_conf(pk, sig, msg, seed, addr, default_wots_config);
}

void wots_verify_conf(unsigned char pk[WOTS_L*HASH_BYTES],
                      const unsigned char sig[WOTS_L*HASH_BYTES],
                      const unsigned char msg[HASH_BYTES],
                      const unsigned char seed[PUBLIC_SEED_BYTES],
                      unsigned char addr[ADDR_BYTES],
                      struct wots_config config)
{
  int basew[config.wots_l],i,c=0;

#if WOTS_W == 16
  for(i=0;i<config.wots_l1;i+=2)
  {
    basew[i]   = msg[i/2] & 0xf;
    basew[i+1] = msg[i/2] >> 4;
    c += WOTS_W - 1 - basew[i];
    c += WOTS_W - 1 - basew[i+1];
  }

  for( ;i<config.wots_l;i++)
  {
    basew[i] = c & 0xf;
    c >>= 4;
  }

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, WOTS_ADDR);
  for(i=0;i<config.wots_l;i++) {
    *address.wots_ots_index = i;
    gen_chain(pk+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, WOTS_W-1-basew[i], basew[i]);
  }

#elif WOTS_W == 4
  for(i=0;i<config.wots_l1;i+=4)
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

  for( ;i<config.wots_l;i++)
  {
    basew[i] = c & 0x3;
    c >>= 2;
  }

  struct hash_addr address = init_hash_addr(addr);
  set_type(addr, WOTS_ADDR);
  for(i=0;i<config.wots_l;i++) {
    *address.wots_ots_index = i;
    gen_chain(pk+i*HASH_BYTES, sig+i*HASH_BYTES, seed, addr, WOTS_W-1-basew[i], basew[i]);
  }

#else
#error "not yet implemented"
#endif
}
