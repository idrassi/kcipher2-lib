/**
 * @file kcipher2.h
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

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __GNUC__
#define KC_INLINE	static inline __attribute__((always_inline))
#elif defined (_MSC_VER)
#define KC_INLINE	__forceinline
#else
#define KC_INLINE	static inline
#endif

/* macro for memory and data alignment */
#if defined(_MSC_VER)
#define KC_ALIGN(x) __declspec(align(x))
#else
#define KC_ALIGN(x) __attribute__((aligned(x)))
#endif

/**
 * @brief Key size in bytes
 */
#define K2CIPHER_KEY_SIZE 16  

/**
 * @brief IV size in bytes
 */
#define K2CIPHER_IV_SIZE 16

/**
 * @brief KCipher-2 context structure
 *
 * This structure contains the state of the cipher.
 * It should be initialized using k2cipher_init() before use.
 */
typedef struct {
    uint32_t a[5];        /**< A-register state */
    uint32_t b[11];       /**< B-register state */
    uint32_t l1, r1;      /**< Left and right register 1 */
    uint32_t l2, r2;      /**< Left and right register 2 */
    uint32_t iv[4];       /**< Initialization vector */
    uint32_t ik[12];      /**< Internal key state */
    KC_ALIGN(32) uint8_t sbytes[64];    /**< Stream buffer */
    size_t svalid;           /**< Number of valid bytes in stream buffer */
} k2cipher_ctx;

/**
 * @brief Initialize KCipher-2 context
 *
 * @param ctx Pointer to cipher context structure
 * @param key Pointer to 16-byte key
 * @param iv Pointer to 16-byte initialization vector
 *
 * @note Both key and iv must be exactly 16 bytes long
 */
void k2cipher_init(k2cipher_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/**
 * @brief Encrypt or decrypt data using KCipher-2
 *
 * This function performs in-place encryption or decryption of data.
 * The same function is used for both operations as KCipher-2 is a stream cipher.
 *
 * @param ctx Pointer to initialized cipher context
 * @param dst Pointer to output buffer
 * @param src Pointer to input buffer
 * @param len Length of data to process in bytes
 *
 * @note dst and src may point to the same buffer for in-place operation
 */
void k2cipher_crypt(k2cipher_ctx* ctx, uint8_t* dst, const uint8_t* src, size_t len);

/**
 * @brief Generate raw keystream bytes
 *
 * This function generates keystream bytes without encryption/decryption.
 */
void k2cipher_keystream(k2cipher_ctx* ctx, uint8_t* stream, size_t len);

/**
 * @brief Secure cleanup macro for KCipher-2 context
 *
 * This macro securely erases all sensitive data from the context.
 * Uses volatile pointer and memory barrier to prevent compiler optimization.
 *
 * @param ctx Pointer to cipher context to be cleaned
 */

#define K2CIPHER_CLEANUP(ctx) do { \
    if (ctx) { \
        volatile uint8_t* volatile p = (volatile uint8_t* volatile)(ctx); \
        volatile uint8_t v; \
        size_t i; \
        for (i = 0; i < sizeof(k2cipher_ctx); i++) { \
            p[i] = 0; \
            v = p[i]; \
            (void)v; \
        } \
    } \
} while (0)


#ifdef __cplusplus
}
#endif
