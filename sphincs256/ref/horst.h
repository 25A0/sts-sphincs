#ifndef HORST_H
#define HORST_H

#include "params.h"
#include <stdint.h>
#include "hash_address.h"

int horst_sign(unsigned char *sig,
               unsigned char pk[HASH_BYTES],
               unsigned long long *sigbytes,
               const unsigned char seed[SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               const unsigned char m_hash[MSGHASH_BYTES]);

int horst_verify(unsigned char *pk,
                 const unsigned char *sig,
                 unsigned char addr[ADDR_BYTES],
                 const unsigned char m_hash[MSGHASH_BYTES]);

#endif
