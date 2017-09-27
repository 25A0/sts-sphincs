/* Initialize a new context based on the given secret key.
 * If a negative value is passed as the subtree index (subtree_idx),
 * a random subtree will be used.
 * If a subtree index between 0 and 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT)
 * is passed, then that index will be used. The initialization will fail
 * with values larger than 1 << (TOTALTREE_HEIGHT - SUBTREE_HEIGHT).
 */
int crypto_context_init(unsigned char *context, unsigned long long *clen,
                        const unsigned char *sk, long long subtree_idx);

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
