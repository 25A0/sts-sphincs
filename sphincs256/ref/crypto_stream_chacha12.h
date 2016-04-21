#include <stdint.h>

#define crypto_stream_chacha12_KEYBYTES 32
#define crypto_stream_chacha12_NONCEBYTES 8

typedef uint32_t u32 ;
typedef unsigned char byte ;

void crypto_stream_chacha12(unsigned char *r, 
                            unsigned long long rlen, 
                            unsigned char nonce[crypto_stream_chacha12_NONCEBYTES],
                            const unsigned char key[crypto_stream_chacha12_KEYBYTES]);
