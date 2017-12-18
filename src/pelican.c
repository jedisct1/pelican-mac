#include "pelican.h"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC target("ssse3")
#pragma GCC target("aes")
#endif

#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#if defined(__IBMC__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

typedef struct CRYPTO_ALIGN(16) _pelican_state {
    __m128i round_keys[pelican_ROUNDS + 1];
} _pelican_state;

#if defined(__IBMC__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
#pragma pack()
#else
#pragma pack(pop)
#endif

#if pelican_ROUNDS == 10
#define DRC(ROUND, RC)                                                     \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t1, (RC));           \
        round_keys[ROUND] = t1;                                            \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));      \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 8));      \
        t1                = _mm_xor_si128(t1, _mm_shuffle_epi32(s, 0xff)); \
    } while (0)

#elif pelican_ROUNDS == 14

#define DRC1(ROUND, RC)                                                    \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t2, (RC));           \
        round_keys[ROUND] = t2;                                            \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));      \
        t1                = _mm_xor_si128(t1, _mm_slli_si128(t1, 8));      \
        t1                = _mm_xor_si128(t1, _mm_shuffle_epi32(s, 0xff)); \
    } while (0)

#define DRC2(ROUND, RC)                                                    \
    do {                                                                   \
        s                 = _mm_aeskeygenassist_si128(t1, (RC));           \
        round_keys[ROUND] = t1;                                            \
        t2                = _mm_xor_si128(t2, _mm_slli_si128(t2, 4));      \
        t2                = _mm_xor_si128(t2, _mm_slli_si128(t2, 8));      \
        t2                = _mm_xor_si128(t2, _mm_shuffle_epi32(s, 0xaa)); \
    } while (0)
#endif

#if pelican_ROUNDS == 10
static void
_aes_key_expand_128(__m128i round_keys[pelican_ROUNDS + 1], __m128i t1)
{
    __m128i s;

    DRC(0, 1);
    DRC(1, 2);
    DRC(2, 4);
    DRC(3, 8);
    DRC(4, 16);
    DRC(5, 32);
    DRC(6, 64);
    DRC(7, 128);
    DRC(8, 27);
    DRC(9, 54);
    round_keys[10] = t1;
}

#elif pelican_ROUNDS == 14

static void
_aes_key_expand_256(__m128i round_keys[pelican_ROUNDS + 1], __m128i t1, __m128i t2)
{
    __m128i s;

    round_keys[0] = t1;
    DRC1(1, 1);
    DRC2(2, 1);
    DRC1(3, 2);
    DRC2(4, 2);
    DRC1(5, 4);
    DRC2(6, 4);
    DRC1(7, 8);
    DRC2(8, 8);
    DRC1(9, 16);
    DRC2(10, 16);
    DRC1(11, 32);
    DRC2(12, 32);
    DRC1(13, 64);
    round_keys[14] = t1;
}
#endif

static void
_pelican(_pelican_state *_st, unsigned char out[pelican_BYTES], const unsigned char *buf,
         size_t buf_len)
{
    CRYPTO_ALIGN(16) unsigned char t[16];
    const __m128i is = _mm_set_epi64x(UINT64_C(0x0100010001010100), UINT64_C(0x0000000001010001));
    __m128i *     round_keys = _st->round_keys;
    __m128i       c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i       r;
    size_t        i;
    size_t        remaining;

#if pelican_ROUNDS == 10
#define COMPUTE_AES_ROUNDS(IN)                                                   \
    do {                                                                         \
        r = _mm_aesenc_si128(_mm_xor_si128((IN), round_keys[0]), round_keys[1]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[2]), round_keys[3]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[4]), round_keys[5]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[6]), round_keys[7]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[8]), round_keys[9]); \
        r = _mm_aesenclast_si128(r, round_keys[10]);                             \
    } while (0)

#elif pelican_ROUNDS == 14

#define COMPUTE_AES_ROUNDS(IN)                                                     \
    do {                                                                           \
        r = _mm_aesenc_si128(_mm_xor_si128((IN), round_keys[0]), round_keys[1]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[2]), round_keys[3]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[4]), round_keys[5]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[6]), round_keys[7]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[8]), round_keys[9]);   \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[10]), round_keys[11]); \
        r = _mm_aesenc_si128(_mm_aesenc_si128(r, round_keys[12]), round_keys[13]); \
        r = _mm_aesenclast_si128(r, round_keys[14]);                               \
    } while (0)
#endif

#define COMPUTE_PELICAN_ROUNDS(IN)                     \
    do {                                               \
        r = _mm_aesenc_si128(IN, _mm_setzero_si128()); \
        r = _mm_aesenc_si128(r, _mm_setzero_si128());  \
        r = _mm_aesenc_si128(r, _mm_setzero_si128());  \
        r = _mm_aesenc_si128(r, _mm_setzero_si128());  \
    } while (0)

    COMPUTE_AES_ROUNDS(is);

    remaining = buf_len;
    while (remaining >= 128) {
        c0 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 0));
        c1 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 16));
        c2 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 32));
        c3 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 48));
        c4 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 64));
        c5 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 80));
        c6 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 96));
        c7 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 112));
        r  = _mm_xor_si128(c0, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c1, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c2, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c3, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c4, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c5, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c6, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c7, r);
        COMPUTE_PELICAN_ROUNDS(r);
        buf += 128;
        remaining -= 128;
    }
    while (remaining >= 32) {
        c0 = _mm_loadu_si128((const __m128i *) (const void *) buf);
        c1 = _mm_loadu_si128((const __m128i *) (const void *) (buf + 16));
        r  = _mm_xor_si128(c0, r);
        COMPUTE_PELICAN_ROUNDS(r);
        r = _mm_xor_si128(c1, r);
        COMPUTE_PELICAN_ROUNDS(r);
        buf += 32;
        remaining -= 32;
    }
    while (remaining >= 16) {
        r = _mm_xor_si128(_mm_loadu_si128((const __m128i *) (const void *) buf), r);
        COMPUTE_PELICAN_ROUNDS(r);
        buf += 16;
        remaining -= 16;
    }

    for (i = 0; i < sizeof t; i++) {
        t[i] = 0U;
    }
    for (i = 0; i < remaining; i++) {
        t[i] = buf[i];
    }
    t[i] = 0x80;
    r    = _mm_xor_si128(_mm_loadu_si128((const __m128i *) (const void *) t), r);

    COMPUTE_AES_ROUNDS(r);
    _mm_storeu_si128((__m128i *) (void *) out, r);
}

void
pelican_init(pelican_state *st, const unsigned char key[pelican_KEYBYTES])
{
    _pelican_state *_st = (_pelican_state *) (void *) st;

    COMPILER_ASSERT(sizeof *st >= sizeof *_st);

#if pelican_ROUNDS == 10
    _aes_key_expand_128(_st->round_keys, _mm_loadu_si128((const __m128i *) (const void *) key));
#elif pelican_ROUNDS == 14
    _aes_key_expand_256(_st->round_keys, _mm_loadu_si128((const __m128i *) (const void *) key),
                        _mm_loadu_si128((const __m128i *) (const void *) (key + 16)));
#endif
}

void
pelican(pelican_state *st, unsigned char out[pelican_BYTES], const unsigned char *buf,
        size_t buf_len)
{
    _pelican((_pelican_state *) (void *) st, out, buf, buf_len);
}
