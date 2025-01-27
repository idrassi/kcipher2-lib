/**
 * @file kcipher2-test.c
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

#include "kcipher2.h"
#include "cpu_cycles.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/* Structure to hold test vectors */
typedef struct {
    const char* key;
    const char* iv;
    const char* keystream;
} test_vector;

/* Test vectors from RFC 7008 */
static const test_vector test_vectors[] = {
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "F871EBEF945B7272E40C04941DFF05370B981A59FBC8AC57566D3B02C179DBB4"
        "3B46F1F033554C725DE68BCC9872858F575496024062F0E9F932C998226DB6BA"
    },
    {
        "A37B7D012F897076FE08C22D142BB2CF",
        "33A6EE60E57927E08B45CC4CA30EDE4A",
        "60E9A6B67B4C2524FE726D44AD5B402E31D0D1BA5CA233A4AFC74BE7D6069D36"
        "4A75BB6CD8D5B7F038AAAA284AE4CD2FE2E5313DFC6CCD8F9D2484F20F86C50D"
    },
    {
        "3D62E9B18E5B042F42DF43CC7175C96E",
        "777CEFE4541300C8ADCACA8A0B48CD55",
        "690F108D84F44AC7BF257BD7E394F6C9AA1192C38E200C6E073C8078AC18AAD1"
        "D4B8DADE688023682FA4207683DEA5A44C1D95EAE959F5B42611F41EA40F0A58"
    },
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "F871EBEF945B7272E40C04941DFF05370B981A59FBC8AC57566D3B02C179DBB4"
        "3B46F1F033554C725DE68BCC9872858F575496024062F0E9F932C99822"
    },
    {
        "A37B7D012F897076FE08C22D142BB2CF",
        "33A6EE60E57927E08B45CC4CA30EDE4A",
        "60E9A6B67B4C2524FE726D44AD5B402E31D0D1BA5CA233A4AFC74BE7D6069D36"
        "4A75BB6CD8D5B7F038AAAA284AE4CD2FE2E5313DFC6CCD8F9D2484F20F86"
    },
    {
        "3D62E9B18E5B042F42DF43CC7175C96E",
        "777CEFE4541300C8ADCACA8A0B48CD55",
        "690F108D84F44AC7BF257BD7E394F6C9AA1192C38E200C6E073C8078AC18AAD1"
        "D4B8DADE688023682FA4207683DEA5A44C1D95EAE959F5B42611F41E"
    },
    {
        "3D62E9B18E5B042F42DF43CC7175C96E",
        "777CEFE4541300C8ADCACA8A0B48CD55",
        "690F108D84F44AC7BF257BD7E394F6C9AA1192C38E200C6E073C8078AC18AAD1"
        "D4B8DADE688023682FA4207683DEA5A44C1D95EAE959F5B42611F4"
    }
};

/**
 * @brief Convert hex string to bytes
 *
 * @param hex Input hex string
 * @param bytes Output byte array
 * @param len Expected length of output in bytes
 * @return int 0 on success, -1 on error
 */
static size_t hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    size_t i, hex_len = strlen(hex);
    if ((hex_len%2) || hex_len > len * 2) return 0;

    for (i = 0; i < (hex_len/2); i++) {
        char hex_byte[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char* end;
        bytes[i] = (uint8_t)strtol(hex_byte, &end, 16);
        if (*end != 0) return 0;
    }
    return hex_len / 2;
}

/**
 * @brief Run KCipher-2 test vectors
 *
 * @return int Number of failed tests (0 if all passed)
 */
int k2cipher_run_tests(void) {
    int failed_tests = 0;
    size_t i, j;
    const size_t num_tests = sizeof(test_vectors) / sizeof(test_vectors[0]); 

    printf("Running KCipher-2 test vectors...\n");
    printf("==================================\n\n");

    for (i = 0; i < num_tests; i++) {
        k2cipher_ctx ctx;
        uint8_t key[K2CIPHER_KEY_SIZE];
        uint8_t iv[K2CIPHER_IV_SIZE];
        uint8_t expected_keystream[64];
        uint8_t actual_keystream[64] = { 0 }; // Initialize to zeros
        size_t keystream_len = 64; // max length of keystream in test vectors
        int test_failed = 0;

        printf("Test Vector %zu:\n", i + 1);
        printf("-------------\n");

        /* Convert hex strings to bytes */
        if (hex_to_bytes(test_vectors[i].key, key, K2CIPHER_KEY_SIZE) == 0) {
            printf("Error: Invalid key hex string\n");
            failed_tests++;
            continue;
        }

        if (hex_to_bytes(test_vectors[i].iv, iv, K2CIPHER_IV_SIZE) == 0) {
            printf("Error: Invalid IV hex string\n");
            failed_tests++;
            continue;
        }

        if ((keystream_len = hex_to_bytes(test_vectors[i].keystream, expected_keystream, keystream_len)) == 0) {
            printf("Error: Invalid keystream hex string\n");
            failed_tests++;
            continue;
        }

        /* Initialize cipher */
        k2cipher_init(&ctx, key, iv);

        /* Generate keystream by encrypting zeros */
        k2cipher_crypt(&ctx, actual_keystream, actual_keystream, keystream_len);

        /* Compare results */
        if (memcmp(actual_keystream, expected_keystream, keystream_len) != 0) {
            test_failed = 1;
            failed_tests++;

            printf("FAILED!\n");
            printf("Key:       ");
            for (j = 0; j < K2CIPHER_KEY_SIZE; j++) {
                printf("%02X", key[j]);
            }
            printf("\nIV:        ");
            for (j = 0; j < K2CIPHER_IV_SIZE; j++) {
                printf("%02X", iv[j]);
            }
            printf("\nExpected:  ");
            for (j = 0; j < keystream_len; j++) {
                printf("%02X", expected_keystream[j]);
            }
            printf("\nGot:       ");
            for (j = 0; j < keystream_len; j++) {
                printf("%02X", actual_keystream[j]);
            }
            printf("\n");
        }
        else {
            printf("PASSED!\n");
        }

        /* Clean up */
        K2CIPHER_CLEANUP(&ctx);
        printf("\n");
    }

    /* Print summary */
    printf("Test Summary:\n");
    printf("-------------\n");
    printf("Total Tests: %zu\n", num_tests);
    printf("Passed:      %zu\n", num_tests - failed_tests);
    printf("Failed:      %d\n", failed_tests);

    return failed_tests;
}

/**
 * @brief Structure to hold benchmark results
 */
typedef struct {
    double mbps;              /* Megabytes per second */
    double mbs;               /* Megabits per second */
    double seconds;           /* Time taken */
    double cycles_per_byte;   /* CPU cycles per byte (if available) */
    size_t bytes_processed;   /* Total bytes processed */
} k2cipher_benchmark_result;

/**
 * @brief Perform benchmark of KCipher-2 implementation
 *
 * @param data_size Size of data to process in bytes
 * @param iterations Number of iterations to perform
 * @param print_results Whether to print results to console
 * @return k2cipher_benchmark_result Structure containing benchmark results
 */
k2cipher_benchmark_result k2cipher_benchmark(size_t data_size, int iterations, int print_results) {
    k2cipher_benchmark_result result = { 0 };
    k2cipher_ctx ctx;
    uint8_t* data, * encrypted;
    uint8_t key[K2CIPHER_KEY_SIZE];
    uint8_t iv[K2CIPHER_IV_SIZE];

    double total_time = 0.0;
    uint64_t start_cycles = 0, end_cycles = 0, total_cycles = 0;
    int i;

    /* Allocate buffers */
    data = (uint8_t*)malloc(data_size);
    encrypted = (uint8_t*)malloc(data_size);
    if (!data || !encrypted) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }

    /* Generate random key, IV and data */
    for (size_t i = 0; i < K2CIPHER_KEY_SIZE; i++) {
        key[i] = (uint8_t)rand();
    }
    for (size_t i = 0; i < K2CIPHER_IV_SIZE; i++) {
        iv[i] = (uint8_t)rand();
    }
    for (size_t i = 0; i < data_size; i++) {
        data[i] = (uint8_t)rand();
    }

    /* Warmup run */
    k2cipher_init(&ctx, key, iv);
    k2cipher_crypt(&ctx, encrypted, data, data_size);

    /* Benchmark loop */
    for (i = 0; i < iterations; i++) {
        /* Initialize cipher */
        k2cipher_init(&ctx, key, iv);

        /* Get start time and cycles */
        start_cycles = cpucycles();

#ifdef _WIN32
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
#else
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif

        /* Perform encryption */
        k2cipher_crypt(&ctx, encrypted, data, data_size);

        /* Get end time and cycles */
#ifdef _WIN32
        QueryPerformanceCounter(&end);
        total_time += (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
#else
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        total_time += (end_time.tv_sec - start_time.tv_sec) +
            (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
#endif

        end_cycles = cpucycles();
        total_cycles += (end_cycles - start_cycles);

        K2CIPHER_CLEANUP(&ctx);
    }

    /* Calculate results */
    result.seconds = total_time / iterations;
    result.bytes_processed = data_size;
    result.mbps = (data_size / (1024.0 * 1024.0)) / result.seconds;
    result.mbs = result.mbps * 8;

    result.cycles_per_byte = cpucycles_per_byte(total_cycles, (iterations * data_size));


    /* Print results if requested */
    if (print_results) {
        printf("\nKCipher-2 Benchmark Results:\n");
        printf("------------------------\n");
        printf("Data size:        %zu bytes\n", data_size);
        printf("Iterations:       %d\n", iterations);
        printf("Time per run:     %.6f seconds\n", result.seconds);
        printf("Throughput:       %.2f MB/s\n", result.mbps);
        printf("                  %.2f Mb/s\n", result.mbs);
        printf("Cycles per byte:  %.2f\n", result.cycles_per_byte);
        printf("------------------------\n");
    }

    /* Cleanup */
    free(data);
    free(encrypted);

    return result;
}

void print_benchmark() {
    const size_t sizes[] = {
        1024,              /* 1 KB */
        64 * 1024,        /* 64 KB */
        1024 * 1024,      /* 1 MB */
        10 * 1024 * 1024,  /* 10 MB */
		100 * 1024 * 1024  /* 100 MB */
    };
	const char* size_names[] = { "1 KB", "64 KB", "1 MB", "10 MB", "100 MB" };
    size_t i;
    k2cipher_benchmark_result result;

    printf("\nComprehensive benchmark suite:\n");
    printf("==============================\n");

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        printf("\nTesting with %s data:\n", size_names[i]);
        result = k2cipher_benchmark(sizes[i], 30, 1);

        if (result.mbps < 100) {
            printf("Warning: Performance below 100 MB/s\n");
        }
    }
}


int main() {
    int failed_tests = k2cipher_run_tests();
    if (failed_tests > 0) {
        printf("\nWARNING: Some tests failed!\n");
        return 1;
    }

	/* Run speed benchmark */
	print_benchmark();

    return 0;
}
