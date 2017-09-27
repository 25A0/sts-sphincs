#ifndef WOTS_H
#define WOTS_H

#include "params.h"
#include "hash_address.h"

void wots_pkgen(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                unsigned char addr[ADDR_BYTES]);

void wots_sign(unsigned char sig[WOTS_L*HASH_BYTES],
               const unsigned char msg[HASH_BYTES],
               const unsigned char sk[SEED_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES]);

void wots_verify(unsigned char pk[WOTS_L*HASH_BYTES],
                 const unsigned char sig[WOTS_L*HASH_BYTES],
                 const unsigned char msg[HASH_BYTES],
                 const unsigned char seed[PUBLIC_SEED_BYTES],
                 unsigned char addr[ADDR_BYTES]);

void gen_chain(unsigned char out[HASH_BYTES],
               const unsigned char in[HASH_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               int chainlen,
               int start);
#endif
