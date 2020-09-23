#ifndef pelican_H
#define pelican_H

#include <stdlib.h>

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
# endif
#endif

#ifndef pelican_KEYBYTES
# define pelican_KEYBYTES 16
#endif
#if pelican_KEYBYTES == 16
# define pelican_ROUNDS 10
#elif pelican_KEYBYTES == 32
# define pelican_ROUNDS 14
#else
# error Unsupported key size
#endif

#define pelican_BYTES 16

typedef struct CRYPTO_ALIGN(16) pelican_state {
    unsigned char opaque[((pelican_ROUNDS) + 1) * 16 + 16];
} pelican_state;

void pelican_init(pelican_state *st,
                  const unsigned char key[pelican_KEYBYTES]);

void
pelican(pelican_state *st, unsigned char out[pelican_BYTES],
        const unsigned char *buf, size_t buf_len);

#endif
