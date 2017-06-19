#ifndef WOTS_H
#define WOTS_H

#include "params.h"
#include "hash_address.h"

// For subtree batch signing, WOTS is used with two different configurations,
// since the size of the input differs for those two scenarios. This struct
// contains parameters of WOTS that are normally configured through #define
// statements. Note that some of this information is redundant. The integrity
// of the configuration will not be checked, though.
// The parameters WOTS_W and WOTS_LOG_W are not stored in this struct since
// they are currently the same for all used configurations.
struct wots_config {
  unsigned int wots_l;
  unsigned int wots_l1;
  unsigned int wots_log_l;
  unsigned int wots_sigbytes;
};

// Generate key pair using default configuration
void wots_pkgen(unsigned char pk[WOTS_L*HASH_BYTES],
                const unsigned char sk[SEED_BYTES],
                const unsigned char seed[PUBLIC_SEED_BYTES],
                unsigned char addr[ADDR_BYTES]);

// Generate key pair with specific configuration
void wots_pkgen_conf(unsigned char pk[WOTS_L*HASH_BYTES],
                     const unsigned char sk[SEED_BYTES],
                     const unsigned char seed[PUBLIC_SEED_BYTES],
                     unsigned char addr[ADDR_BYTES],
                     struct wots_config);

// Sign a message msg using the default configuration
void wots_sign(unsigned char sig[WOTS_L*HASH_BYTES],
               const unsigned char msg[HASH_BYTES],
               const unsigned char sk[SEED_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES]);

// Sign a message msg using a specific configuration
void wots_sign_conf(unsigned char sig[WOTS_L*HASH_BYTES],
                    const unsigned char msg[HASH_BYTES],
                    const unsigned char sk[SEED_BYTES],
                    const unsigned char seed[PUBLIC_SEED_BYTES],
                    unsigned char addr[ADDR_BYTES],
                    struct wots_config);

// Verify a signature using the default configuration
void wots_verify(unsigned char pk[WOTS_L*HASH_BYTES],
                 const unsigned char sig[WOTS_L*HASH_BYTES],
                 const unsigned char msg[HASH_BYTES],
                 const unsigned char seed[PUBLIC_SEED_BYTES],
                 unsigned char addr[ADDR_BYTES]);

// Verify a message using a specific configuration
void wots_verify_conf(unsigned char pk[WOTS_L*HASH_BYTES],
                      const unsigned char sig[WOTS_L*HASH_BYTES],
                      const unsigned char msg[HASH_BYTES],
                      const unsigned char seed[PUBLIC_SEED_BYTES],
                      unsigned char addr[ADDR_BYTES],
                      struct wots_config);

void gen_chain(unsigned char out[HASH_BYTES],
               const unsigned char in[HASH_BYTES],
               const unsigned char seed[PUBLIC_SEED_BYTES],
               unsigned char addr[ADDR_BYTES],
               int chainlen,
               int start);
#endif
