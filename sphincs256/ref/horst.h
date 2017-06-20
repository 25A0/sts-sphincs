#ifndef HORST_H
#define HORST_H

#include "params.h"
#include <stdint.h>
#include "hash_address.h"

// horst_t and horst_logt are not configurable for now.
struct horst_config {
  unsigned int horst_k;
  unsigned int horst_sigbytes;
};

extern struct horst_config default_horst_config;

int horst_sign(unsigned char *sig,
               unsigned char pk[HASH_BYTES],
               unsigned long long *sigbytes,
               const unsigned char seed[SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               const unsigned char* m, unsigned int mlen);

int horst_sign_conf(unsigned char *sig, unsigned char pk[HASH_BYTES],
                    unsigned long long *sigbytes,
                    const unsigned char seed[SEED_BYTES],
                    unsigned char addr[ADDR_BYTES],
                    const unsigned char* m, unsigned int mlen,
                    struct horst_config config);

int horst_verify(unsigned char *pk,
                 const unsigned char *sig,
                 unsigned char addr[ADDR_BYTES],
                 const unsigned char* m, unsigned int mlen);

int horst_verify_conf(unsigned char *pk,
                      const unsigned char *sig,
                      unsigned char addr[ADDR_BYTES],
                      const unsigned char* m, unsigned int mlen,
                      struct horst_config config);

#endif
