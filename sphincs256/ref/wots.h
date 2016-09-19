#ifndef WOTS_H
#define WOTS_H

#include "params.h"
#include "hash_address.h"

void wots_pkgen(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                uint32_t addr[ADDR_SIZE]);

void wots_sign(unsigned char sig[WOTS_L*HASH_BYTES],
               const unsigned char msg[HASH_BYTES],
               const unsigned char sk[SEED_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               uint32_t addr[ADDR_SIZE]);

void wots_verify(unsigned char pk[WOTS_L*HASH_BYTES],
                 const unsigned char sig[WOTS_L*HASH_BYTES],
                 const unsigned char msg[HASH_BYTES],
                 const unsigned char seed[PUBLIC_SEED_BYTES],
                 uint32_t addr[ADDR_SIZE]);

void gen_chain(unsigned char out[HASH_BYTES],
               const unsigned char in[HASH_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               uint32_t addr[ADDR_SIZE],
               int chainlen,
               int start);
#endif
