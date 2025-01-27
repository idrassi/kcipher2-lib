/**
 * @file kcipher2-generate-tables.c
 * @brief KCipher-2 stream cipher test vectors and performance benchmark
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

#include <stdio.h>
#include <stdint.h>

#ifdef __GNUC__
#define KC_INLINE	static inline __attribute__((always_inline))
#elif defined (_MSC_VER1)
#define KC_INLINE	__forceinline
#else
#define KC_INLINE	static inline
#endif

const uint8_t sBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


 /**
  * @brief GF(2^8) multiplication by 2
  */
KC_INLINE uint8_t gf_mult_by_2(uint8_t t) {
    uint32_t lq = ((uint32_t)t << 1);
    if (lq & 0x100) {
        lq ^= 0x011B;
    }
    return (uint8_t)(lq ^ 0xFF);
}

/**
 * @brief GF(2^8) multiplication by 3
 */
KC_INLINE uint8_t gf_mult_by_3(uint8_t t) {
    uint32_t lq = ((uint32_t)t << 1) ^ t;
    if (lq & 0x100) {
        lq ^= 0x011B;
    }
    return (uint8_t)(lq ^ 0xFF);
}

/* -------------------------------------------------------------------------
 * 3) Reference sub_k2() from KCipher-2 code
 * ------------------------------------------------------------------------- */
static uint32_t sub_k2_reference(uint32_t in)
{
    /* Extract bytes */
    uint8_t w0 = (uint8_t)(in & 0xFF);
    uint8_t w1 = (uint8_t)((in >> 8) & 0xFF);
    uint8_t w2 = (uint8_t)((in >> 16) & 0xFF);
    uint8_t w3 = (uint8_t)((in >> 24) & 0xFF);

    /* Apply s-box */
    uint8_t t0 = sBox[w0];
    uint8_t t1 = sBox[w1];
    uint8_t t2 = sBox[w2];
    uint8_t t3 = sBox[w3];

    /* Mix (q3,q2,q1,q0) */
    uint8_t q0 = gf_mult_by_2(t0) ^ gf_mult_by_3(t1) ^ t2 ^ t3;
    uint8_t q1 = t0 ^ gf_mult_by_2(t1) ^ gf_mult_by_3(t2) ^ t3;
    uint8_t q2 = t0 ^ t1 ^ gf_mult_by_2(t2) ^ gf_mult_by_3(t3);
    uint8_t q3 = gf_mult_by_3(t0) ^ t1 ^ t2 ^ gf_mult_by_2(t3);

    /* Pack into 32 bits in [q3 q2 q1 q0] order */
    uint32_t out = ((uint32_t)q3 << 24) |
        ((uint32_t)q2 << 16) |
        ((uint32_t)q1 << 8) |
        (uint32_t)q0;
    return out;
}

/* -------------------------------------------------------------------------
 * 4) Our T-tables (to be generated).
 * ------------------------------------------------------------------------- */
static uint32_t T0[256];
static uint32_t T1[256];
static uint32_t T2[256];
static uint32_t T3[256];

/* -------------------------------------------------------------------------
 * 5) Program entry: generate T-tables and print them in C-friendly format
 * ------------------------------------------------------------------------- */

void generate_T0()
{
	uint16_t w0 = 0;
	for (w0 = 0; w0 < 256; w0++)
	{
		/* Extract bytes */
		uint8_t t0 = sBox[(uint8_t)w0];
		/* Mix (q3,q2,q1,q0) */
		uint8_t q0 = gf_mult_by_2(t0);
		uint8_t q1 = t0;
		uint8_t q2 = t0;
		uint8_t q3 = gf_mult_by_3(t0);
		/* Pack into 32 bits in [q3 q2 q1 q0] order */
		uint32_t out = ((uint32_t)q3 << 24) |
			((uint32_t)q2 << 16) |
			((uint32_t)q1 << 8) |
			(uint32_t)q0;
		T0[w0] = out;
	}
}

void generate_T1 ()
{
	uint16_t w1 = 0;
	for (w1 = 0; w1 < 256; w1++)
	{
		/* Extract bytes */
		uint8_t t1 = sBox[(uint8_t)w1];
		/* Mix (q3,q2,q1,q0) */
		uint8_t q0 = gf_mult_by_3(t1);
		uint8_t q1 = gf_mult_by_2(t1);
		uint8_t q2 = t1;
		uint8_t q3 = t1;
		/* Pack into 32 bits in [q3 q2 q1 q0] order */
		uint32_t out = ((uint32_t)q3 << 24) |
			((uint32_t)q2 << 16) |
			((uint32_t)q1 << 8) |
			(uint32_t)q0;
		T1[w1] = out;
	}
}

void generate_T2()
{
	uint16_t w2 = 0;
	for (w2 = 0; w2 < 256; w2++)
	{
		/* Extract bytes */
		uint8_t t2 = sBox[(uint8_t)w2];
		/* Mix (q3,q2,q1,q0) */
		uint8_t q0 = t2;
		uint8_t q1 = gf_mult_by_3(t2);
		uint8_t q2 = gf_mult_by_2(t2);
		uint8_t q3 = t2;
		/* Pack into 32 bits in [q3 q2 q1 q0] order */
		uint32_t out = ((uint32_t)q3 << 24) |
			((uint32_t)q2 << 16) |
			((uint32_t)q1 << 8) |
			(uint32_t)q0;
		T2[w2] = out;
	}
}

void generate_T3()
{
    uint16_t w3 = 0;
    for (w3 = 0; w3 < 256; w3++)
    {
        /* Extract bytes */
        uint8_t t3 = sBox[(uint8_t)w3];
        /* Mix (q3,q2,q1,q0) */
        uint8_t q0 = t3;
        uint8_t q1 = t3;
        uint8_t q2 = gf_mult_by_3(t3);
        uint8_t q3 = gf_mult_by_2(t3);
        /* Pack into 32 bits in [q3 q2 q1 q0] order */
        uint32_t out = ((uint32_t)q3 << 24) |
            ((uint32_t)q2 << 16) |
            ((uint32_t)q1 << 8) |
            (uint32_t)q0;
        T3[w3] = out;
    }
}

int main(void)
{
	int i;
    /* Generate the tables */
    generate_T0();
	generate_T1();
	generate_T2();
	generate_T3();

    /* Print the tables. You can copy these into your code. */
    printf("const KC_ALIGN(16) uint32_t T0[256] = {\n");
    for (i = 0; i < 256; i++) {
        printf("0x%08X", T0[i]);
        if (i < 255) printf(", ");
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("};\n\n");

    printf("const KC_ALIGN(16) uint32_t T1[256] = {\n");
    for (i = 0; i < 256; i++) {
        printf("0x%08X", T1[i]);
        if (i < 255) printf(", ");
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("};\n\n");

    printf("const KC_ALIGN(16) uint32_t T2[256] = {\n");
    for (i = 0; i < 256; i++) {
        printf("0x%08X", T2[i]);
        if (i < 255) printf(", ");
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("};\n\n");

    printf("const KC_ALIGN(16) uint32_t T3[256] = {\n");
    for (i = 0; i < 256; i++) {
        printf("0x%08X", T3[i]);
        if (i < 255) printf(", ");
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("};\n");

    return 0;
}

