int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen, 
                const unsigned char *m,unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open(unsigned char *m,unsigned long long *mlen, 
                     const unsigned char *sm,unsigned long long smlen,
                     const unsigned char *pk);

int crypto_context_init(unsigned char *context, unsigned long long *clen,
                        const unsigned char *sk, const unsigned char *seed);

int crypto_sign_full(unsigned char *m, unsigned long long mlen,
                     unsigned char *context, unsigned long long *clen,
                     unsigned char *sig, unsigned long long *slen,
                     const unsigned char *sk);

int crypto_sign_update(unsigned char *m, unsigned long long mlen,
                       unsigned char *context, unsigned long long *clen,
                       unsigned char *sig, unsigned long long *slen,
                       const unsigned char *sk);

int crypto_sign_open_full(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk);

int crypto_sign_open_update(unsigned char *m, unsigned long long *mlen,
                            const unsigned char* context, unsigned long long *clen,
                            const unsigned char* sig, unsigned long long smlen,
                            const unsigned char *pk);
