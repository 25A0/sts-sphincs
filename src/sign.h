#ifndef SIGN_H
#define SIGN_H

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen, 
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m,unsigned long long *mlen, 
                     const unsigned char *sm,unsigned long long smlen,
                     const unsigned char *pk);

struct signature {
  // The hash seed that was used to hash the message
  unsigned char* message_hash_seed;
  // The index of the HORST leaf that signed the message
  unsigned char* leafidx;
  // The HORST signature of the message
  unsigned char* horst_signature;
  // The WOTS signatures that verify the HORST signature under the used key pair
  unsigned char* wots_signatures;

  // The signature always contains a copy of the message at the very end
  unsigned char* message;
};

struct signature init_signature(unsigned char* bytes);

void write_ull(unsigned char* buf, const unsigned long long ull,
                      const unsigned int bytes);

unsigned long long read_ull(unsigned char* buf, const unsigned int bytes);

const unsigned char* get_public_seed_from_pk(const unsigned char* pk);

const unsigned char* get_public_seed_from_sk(const unsigned char* sk);

int get_system_entropy(void* buf, unsigned int length);

#endif
