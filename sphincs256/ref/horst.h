#ifndef HORST_H
#define HORST_H

#include "params.h"
#include <stdint.h>
#include "hash_address.h"

int horst_sign(unsigned char *sig,
               unsigned char pk[HASH_BYTES],
               unsigned long long *sigbytes,
               const unsigned char *m,
               unsigned long long mlen,
               const unsigned char seed[SEED_BYTES],
               uint32_t addr[ADDR_SIZE],
               const unsigned char m_hash[MSGHASH_BYTES]);

int horst_verify(unsigned char *pk,
                 const unsigned char *sig,
                 const unsigned char *m,
                 unsigned long long mlen,
                 uint32_t addr[ADDR_SIZE],
                 const unsigned char m_hash[MSGHASH_BYTES]);

#endif
