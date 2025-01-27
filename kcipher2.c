/**
 * @file kcipher2.c
 * @brief KCipher-2 stream cipher implementation
 *
 * This implementation follows RFC 7008 and the CRYPTREC specification.
 * References:
 * - http://tools.ietf.org/html/rfc7008
 * - https://cryptrec.go.jp/en/cryptrec_13_spec_cypherlist_files/PDF/21_09spec_e_1.2.pdf
 *
 * Copyright (c) 2025 Mounir IDRASSI <mounir@idrix.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "kcipher2.h" 
#include <string.h>
#include <stdlib.h>

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_IX86) || defined(__i386__)
#include <emmintrin.h>
#define K2CIPHER_SIMD
#endif

// Multiplication tables
extern const KC_ALIGN(16) uint32_t amul0[256];
extern const KC_ALIGN(16) uint32_t amul1[256];
extern const KC_ALIGN(16) uint32_t amul2[256];
extern const KC_ALIGN(16) uint32_t amul3[256];

// T-tables
extern const KC_ALIGN(16) uint32_t T0[256];
extern const KC_ALIGN(16) uint32_t T1[256];
extern const KC_ALIGN(16) uint32_t T2[256];
extern const KC_ALIGN(16) uint32_t T3[256];


/* Internal functions */

/**
 * @brief Substitution function
 */
KC_INLINE uint32_t sub_k2(uint32_t in) {
    uint8_t w0 = (uint8_t)in;
    uint8_t w1 = (uint8_t)(in >> 8);
    uint8_t w2 = (uint8_t)(in >> 16);
    uint8_t w3 = (uint8_t)(in >> 24);

    uint32_t result = T0[w0] ^ T1[w1] ^ T2[w2] ^ T3[w3];

    return result;
}

/**
 * @brief Non-linear function
 */
KC_INLINE uint32_t nlf(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    return (a + b) ^ c ^ d;
}

/**
 * @brief Key expansion function
 */
static void key_expansion(k2cipher_ctx* ctx, const uint32_t* key, const uint32_t* iv) {
    /* Copy IV and initial key material */
    memcpy(ctx->iv, iv, sizeof(ctx->iv));
    memcpy(ctx->ik, key, 16);

    /* Expand key */
    ctx->ik[4] = ctx->ik[0] ^ sub_k2((ctx->ik[3] << 8) ^ (ctx->ik[3] >> 24)) ^ 0x01000000;

    ctx->ik[5] = ctx->ik[1] ^ ctx->ik[4];
    ctx->ik[6] = ctx->ik[2] ^ ctx->ik[5];
    ctx->ik[7] = ctx->ik[3] ^ ctx->ik[6];

    ctx->ik[8] = ctx->ik[4] ^ sub_k2((ctx->ik[7] << 8) ^ (ctx->ik[7] >> 24)) ^ 0x02000000;

    ctx->ik[9] = ctx->ik[5] ^ ctx->ik[8];
    ctx->ik[10] = ctx->ik[6] ^ ctx->ik[9];
    ctx->ik[11] = ctx->ik[7] ^ ctx->ik[10];
}

/**
 * @brief Setup initial state values
 */
static void setup_state_values(k2cipher_ctx* ctx, const uint32_t* key, const uint32_t* iv) {
    key_expansion(ctx, key, iv);

    /* Initialize A registers */
    ctx->a[0] = ctx->ik[4];
    ctx->a[1] = ctx->ik[3];
    ctx->a[2] = ctx->ik[2];
    ctx->a[3] = ctx->ik[1];
    ctx->a[4] = ctx->ik[0];

    /* Initialize B registers */
    ctx->b[0] = ctx->ik[10];
    ctx->b[1] = ctx->ik[11];
    ctx->b[2] = ctx->iv[0];
    ctx->b[3] = ctx->iv[1];
    ctx->b[4] = ctx->ik[8];
    ctx->b[5] = ctx->ik[9];
    ctx->b[6] = ctx->iv[2];
    ctx->b[7] = ctx->iv[3];
    ctx->b[8] = ctx->ik[7];
    ctx->b[9] = ctx->ik[5];
    ctx->b[10] = ctx->ik[6];

    /* Clear registers */
    ctx->l1 = ctx->r1 = ctx->l2 = ctx->r2 = 0;
}

/**
 * @brief Next state function
 */
static void next_for_init(k2cipher_ctx* ctx) {
    uint32_t nA[5], nB[11];
    uint32_t temp1, temp2;

    uint32_t nL1 = sub_k2(ctx->r2 + ctx->b[4]);
    uint32_t nR1 = sub_k2(ctx->l2 + ctx->b[9]);
    uint32_t nL2 = sub_k2(ctx->l1);
    uint32_t nR2 = sub_k2(ctx->r1);

    /* Shift A registers */
    nA[0] = ctx->a[1];
    nA[1] = ctx->a[2];
    nA[2] = ctx->a[3];
    nA[3] = ctx->a[4];

    /* Shift B registers */
    nB[0] = ctx->b[1];
    nB[1] = ctx->b[2];
    nB[2] = ctx->b[3];
    nB[3] = ctx->b[4];
    nB[4] = ctx->b[5];
    nB[5] = ctx->b[6];
    nB[6] = ctx->b[7];
    nB[7] = ctx->b[8];
    nB[8] = ctx->b[9];
    nB[9] = ctx->b[10];

    /* Update A[4] */
    temp1 = (ctx->a[0] << 8) ^ amul0[ctx->a[0] >> 24];
    nA[4] = temp1 ^ ctx->a[3];
    nA[4] ^= nlf(ctx->b[0], ctx->r2, ctx->r1, ctx->a[4]);

    /* Update B[10] */
    if (ctx->a[2] & 0x40000000) {
        temp1 = (ctx->b[0] << 8) ^ amul1[ctx->b[0] >> 24];
    }
    else {
        temp1 = (ctx->b[0] << 8) ^ amul2[ctx->b[0] >> 24];
    }

    if (ctx->a[2] & 0x80000000) {
        temp2 = (ctx->b[8] << 8) ^ amul3[ctx->b[8] >> 24];
    }
    else {
        temp2 = ctx->b[8];
    }

    nB[10] = temp1 ^ ctx->b[1] ^ ctx->b[6] ^ temp2;
    nB[10] ^= nlf(ctx->b[10], ctx->l2, ctx->l1, ctx->a[0]);

    /* Update state */
    ctx->a[0] = nA[0];
    ctx->a[1] = nA[1];
    ctx->a[2] = nA[2];
    ctx->a[3] = nA[3];
    ctx->a[4] = nA[4];

    ctx->b[0] = nB[0];
    ctx->b[1] = nB[1];
    ctx->b[2] = nB[2];
    ctx->b[3] = nB[3];
    ctx->b[4] = nB[4];
    ctx->b[5] = nB[5];
    ctx->b[6] = nB[6];
    ctx->b[7] = nB[7];
    ctx->b[8] = nB[8];
    ctx->b[9] = nB[9];
    ctx->b[10] = nB[10];

    ctx->l1 = nL1;
    ctx->r1 = nR1;
    ctx->l2 = nL2;
    ctx->r2 = nR2;
}

static void next(k2cipher_ctx* ctx) {
    uint32_t nA[5], nB[11];
    uint32_t temp1, temp2, temp2_cond, mask;
    const uint32_t* ptr;
    uint8_t b8;

    uint32_t nL1 = sub_k2(ctx->r2 + ctx->b[4]);
    uint32_t nR1 = sub_k2(ctx->l2 + ctx->b[9]);
    uint32_t nL2 = sub_k2(ctx->l1);
    uint32_t nR2 = sub_k2(ctx->r1);

    /* Shift A registers */
    nA[0] = ctx->a[1];
    nA[1] = ctx->a[2];
    nA[2] = ctx->a[3];
    nA[3] = ctx->a[4];

    /* Shift B registers */
    nB[0] = ctx->b[1];
    nB[1] = ctx->b[2];
    nB[2] = ctx->b[3];
    nB[3] = ctx->b[4];
    nB[4] = ctx->b[5];
    nB[5] = ctx->b[6];
    nB[6] = ctx->b[7];
    nB[7] = ctx->b[8];
    nB[8] = ctx->b[9];
    nB[9] = ctx->b[10];

    /* Update A[4] */
    temp1 = (ctx->a[0] << 8) ^ amul0[ctx->a[0] >> 24];
    nA[4] = temp1 ^ ctx->a[3];

    /* Update B[10] */

    ptr = (ctx->a[2] & 0x40000000) ? amul1 : amul2;
    temp1 = (ctx->b[0] << 8) ^ ptr[ctx->b[0] >> 24];

    b8 = (uint8_t)(ctx->b[8] >> 24);
    temp2_cond = (ctx->b[8] << 8) ^ amul3[b8];
    mask = (uint32_t)-(int32_t)((ctx->a[2] & 0x80000000) >> 31);
    temp2 = (temp2_cond & mask) | (ctx->b[8] & ~mask);

    nB[10] = temp1 ^ ctx->b[1] ^ ctx->b[6] ^ temp2;

    /* Update state */
    ctx->a[0] = nA[0];
    ctx->a[1] = nA[1];
    ctx->a[2] = nA[2];
    ctx->a[3] = nA[3];
    ctx->a[4] = nA[4];

    ctx->b[0] = nB[0];
    ctx->b[1] = nB[1];
    ctx->b[2] = nB[2];
    ctx->b[3] = nB[3];
    ctx->b[4] = nB[4];
    ctx->b[5] = nB[5];
    ctx->b[6] = nB[6];
    ctx->b[7] = nB[7];
    ctx->b[8] = nB[8];
    ctx->b[9] = nB[9];
    ctx->b[10] = nB[10];

    ctx->l1 = nL1;
    ctx->r1 = nR1;
    ctx->l2 = nL2;
    ctx->r2 = nR2;
}

/**
 * @brief Generate stream values
 */
KC_INLINE void stream(k2cipher_ctx* ctx, uint32_t* zh, uint32_t* zl) {
    *zh = nlf(ctx->b[10], ctx->l2, ctx->l1, ctx->a[0]);
    *zl = nlf(ctx->b[0], ctx->r2, ctx->r1, ctx->a[4]);
}

/* Public functions */
void k2cipher_init(k2cipher_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    uint32_t k32[4], iv32[4];

    /* Convert key and IV to big-endian 32-bit words */
    for (int i = 0; i < 4; i++) {
        k32[i] = ((uint32_t)key[i * 4] << 24) |
            ((uint32_t)key[i * 4 + 1] << 16) |
            ((uint32_t)key[i * 4 + 2] << 8) |
            (uint32_t)key[i * 4 + 3];

        iv32[i] = ((uint32_t)iv[i * 4] << 24) |
            ((uint32_t)iv[i * 4 + 1] << 16) |
            ((uint32_t)iv[i * 4 + 2] << 8) |
            (uint32_t)iv[i * 4 + 3];
    }

    /* Initialize cipher state */
    setup_state_values(ctx, k32, iv32);

    /* Perform initialization rounds */
    for (int i = 0; i < 24; i++) {
        next_for_init(ctx);
    }

    /* Reset stream buffer */
    ctx->svalid = 0;
}

void k2cipher_crypt(k2cipher_ctx* ctx, uint8_t* dst, const uint8_t* src, size_t len)
{
    size_t i = 0, j, chunk, remaining;
    uint8_t* cur_ks = NULL;

    while (i < len)
    {
        // If no valid keystream bytes are left, generate 32 new bytes
        if (ctx->svalid == 0)
        {
            for (j = 0; j < 4; j++)
            {
                uint32_t zh, zl;
                stream(ctx, &zh, &zl);
                next(ctx);


                // Pack zh and zl into ctx->sbytes[] for later XOR
				// Swap bytes for little-endian systems
#ifdef _MSC_VER
				zh = _byteswap_ulong(zh);
				zl = _byteswap_ulong(zl);
#else
				zh = __builtin_bswap32(zh);
				zl = __builtin_bswap32(zl);
#endif

                *((uint32_t*)(&ctx->sbytes[8 * j])) = zh;
				*((uint32_t*)(&ctx->sbytes[8 * j + 4])) = zl;


				// original code before optimization
                //ctx->sbytes[8 * j + 0] = (uint8_t)(zh >> 24);
                //ctx->sbytes[8 * j + 1] = (uint8_t)(zh >> 16);
                //ctx->sbytes[8 * j + 2] = (uint8_t)(zh >> 8);
                //ctx->sbytes[8 * j + 3] = (uint8_t)(zh);
                //ctx->sbytes[8 * j + 4] = (uint8_t)(zl >> 24);
                //ctx->sbytes[8 * j + 5] = (uint8_t)(zl >> 16);
                //ctx->sbytes[8 * j + 6] = (uint8_t)(zl >> 8);
                //ctx->sbytes[8 * j + 7] = (uint8_t)(zl);
            }

            ctx->svalid = 32;
        }

        // Determine how many bytes we can XOR in this iteration
        chunk = (len - i < ctx->svalid) ? (len - i) : ctx->svalid;

        // XOR input data with keystream in chunks
        remaining = chunk;
        cur_ks = &ctx->sbytes[32 - ctx->svalid];

		// in case of x86/x64, use SSE2 instructions to process 32 and 16 bytes at a time
#ifdef K2CIPHER_SIMD
        if (remaining == 32) {
            __m128i xmm0 = _mm_loadu_si128((__m128i*)src);
            __m128i xmm1 = _mm_load_si128((__m128i*)cur_ks);
            __m128i xmm2 = _mm_xor_si128(xmm0, xmm1);
            _mm_storeu_si128((__m128i*)dst, xmm2);
            dst += 16;
            src += 16;
            cur_ks += 16;

            xmm0 = _mm_loadu_si128((__m128i*)src);
            xmm1 = _mm_load_si128((__m128i*)cur_ks);
            xmm2 = _mm_xor_si128(xmm0, xmm1);
            _mm_storeu_si128((__m128i*)dst, xmm2);
            dst += 16;
            src += 16;
            cur_ks += 16;

			remaining = 0;
        }

        else if (remaining >= 16) {
			__m128i xmm0 = _mm_loadu_si128((__m128i*)src);
			__m128i xmm1 = _mm_loadu_si128((__m128i*)cur_ks);
			__m128i xmm2 = _mm_xor_si128(xmm0, xmm1);
			_mm_storeu_si128((__m128i*)dst, xmm2);
			dst += 16;
			src += 16;
			cur_ks += 16;
			remaining -= 16;
		}
#endif
        
        // Process 8 bytes at a time using uint64_t
        while (remaining >= 8) {
            *(uint64_t*)dst = *(uint64_t*)src ^ *(uint64_t*)cur_ks;
            dst += 8;
            src += 8;
            cur_ks += 8;
            remaining -= 8;
        }
        
        // Process 4 bytes at a time using uint32_t
        while (remaining >= 4) {
            *(uint32_t*)dst = *(uint32_t*)src ^ *(uint32_t*)cur_ks;
            dst += 4;
            src += 4;
            cur_ks += 4;
            remaining -= 4;
        }
        
        // Process remaining bytes one at a time
        while (remaining > 0) {
            *dst = *src ^ *cur_ks;
            dst++;
            src++;
            cur_ks++;
            remaining--;
        }

        // Advance pointers/counters
        i += chunk;
        ctx->svalid -= chunk;
    }
}

/**
 * @brief Generate raw keystream bytes
 *
 * This function generates keystream bytes without encryption/decryption.
 */
void k2cipher_keystream(k2cipher_ctx* ctx, uint8_t* stream, size_t len) {
    /* Temporary buffer of zeros */
    uint8_t zeros[256] = { 0 };

    while (len > 0) {
        size_t chunk = (len > sizeof(zeros)) ? sizeof(zeros) : len;
        k2cipher_crypt(ctx, stream, zeros, chunk);
        stream += chunk;
        len -= chunk;
    }
}
