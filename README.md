# KCipher-2 in C

This repository provides a high-performance C implementation of the KCipher-2 stream cipher, compatible with x64 and various other architectures. KCipher-2 is standardized in [RFC 7008](https://tools.ietf.org/html/rfc7008) and recognized by [CRYPTREC](http://www.cryptrec.go.jp/english/cryptrec_13_spec_cypherlist_files/PDF/21_00espec.pdf) in Japan.

## Overview

The repository contains:

- **kcipher2.c / kcipher2.h**  
  The main implementation of the KCipher-2 stream cipher, including:
  - Initialization function `k2cipher_init()`
  - Encryption/Decryption function `k2cipher_crypt()`
  - Keystream generation function `k2cipher_keystream()`
  - Context cleanup macro `K2CIPHER_CLEANUP()`

- **kcipher2-tables.c**  
  Precomputed lookup tables used for the KCipher-2 transformations (multiplication tables, T-tables).

- **kcipher2-generate-tables.c**  
  A command-line program that can generate the T-tables (and related data) using the optimized KCipher-2 code. This helps in creating or verifying the table constants used in `kcipher2-tables.c`.

- **cpu_cycles.h**  
  A header that provides a cross-platform mechanism to measure CPU cycles or high-resolution time, used for benchmarking. It uses RDTSC/RDTSCP on x86/x64, and relevant high-resolution timers on ARM (including Apple Silicon).

- **kcipher2-test.c**  
  A command-line test and benchmark utility that:
  - Validates the implementation against known test vectors from RFC 7008.
  - Performs speed benchmarks on different data sizes and iterations.
  - Demonstrates usage of the cipher API.

- **KCipher-2.sln**  
  A Visual Studio 2022 solution file that provides:
  - A static library build from `kcipher2.c`
  - A test/benchmark executable from `kcipher2-test.c`
  - An executable to generate T-tables from `kcipher2-generate-tables.c`
  
  This solution includes configurations for **Win32**, **x64**, and **ARM64** platforms.

- **LICENSE**  
  The text of the GNU Affero General Public License (AGPL) v3 under which this project is released.

## Features

- **Full KCipher-2 Implementation**  
  Implements the key schedule, state transitions, and stream generation as per the RFC and CRYPTREC specification.

- **High-Performance on 64-bit platforms**  
  Includes optimizations 64-bit architectures, making heavy use of table lookups and minimal branching.  
  Achieves throughputs in the range of 650–850 MB/s on typical modern x64 CPUs (see benchmark data below).

- **Cross-Platform Cycle/Time Measurement**  
  `cpu_cycles.h` supports Windows, Linux, macOS, and ARM64, ensuring benchmarks can be performed on a wide range of hardware.

- **Test Vectors**  
  Includes test vectors from RFC 7008 to verify correctness.

- **Tooling for Table Generation**  
  The optional `kcipher2-generate-tables.c` tool can generate the T-tables for use in `kcipher2-tables.c`, aiding development or verification of lookup tables.

## Building

### Building with Visual Studio (Windows)

Open **KCipher-2.sln** in Visual Studio 2022. The solution contains three main projects:

1. **kcipher2** – Builds a static library from `kcipher2.c`.
2. **kcipher2-test** – Builds the test and benchmark executable from `kcipher2-test.c`.
3. **kcipher2-generate-tables** – Builds the T-tables generator from `kcipher2-generate-tables.c`.

The solution provides configurations for **Win32**, **x64**, and **ARM64**. You can select the desired platform and configuration (e.g., Release x64) from the Visual Studio toolbar, then build and run.

### Building on Linux / macOS

```bash
# Example using GCC or Clang
gcc -O3 -o kcipher2-test kcipher2.c kcipher2-tables.c kcipher2-test.c
gcc -O3 -o kcipher2-generate-tables kcipher2-generate-tables.c
```

### Building on Other Platforms

Adjust the commands accordingly for your compiler and environment.  
Ensure you include all necessary source files (`kcipher2.c`, `kcipher2-tables.c`, and optionally `kcipher2-generate-tables.c`).

## Usage

Below is a brief example showing how you might use KCipher-2 in your own code:

```c
#include "kcipher2.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Sample key and IV (16 bytes each)
    uint8_t key[K2CIPHER_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t iv[K2CIPHER_IV_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0x00
    };

    // Plaintext to encrypt
    const char* plaintext = "Hello, KCipher-2!";
    size_t len = strlen(plaintext);

    // Buffers for encryption and decryption
    uint8_t encrypted[64];
    uint8_t decrypted[64];

    // Initialize cipher context
    k2cipher_ctx ctx;
    k2cipher_init(&ctx, key, iv);

    // Encrypt
    k2cipher_crypt(&ctx, encrypted, (const uint8_t*)plaintext, len);

    // We can re-initialize with the same key/IV to decrypt
    k2cipher_init(&ctx, key, iv);

    // Decrypt
    k2cipher_crypt(&ctx, decrypted, encrypted, len);

    // Add null terminator for printing
    decrypted[len] = '\0';

    printf("Original:  %s\n", plaintext);
    printf("Encrypted: ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    // Secure cleanup
    K2CIPHER_CLEANUP(&ctx);

    return 0;
}
```

## Running Tests and Benchmarks

After building **kcipher2-test** (or compiling `kcipher2-test.c` manually), run:

```bash
./kcipher2-test
```

It will:
1. Validate the implementation with built-in test vectors.
2. Run several benchmarks on different data sizes (e.g., 1 KB, 64 KB, 1 MB, 10 MB, 100 MB).

A typical console output will show test results (PASS/FAIL) and performance metrics (MB/s, cycles/byte, etc.).

## Benchmark Results

Below are example benchmark results measured on an x64 system (numbers will vary based on CPU and OS):

```
KCipher-2 Benchmark Results:
------------------------
Data size:        65536 bytes
Iterations:       30
Time per run:     0.000096 seconds
Throughput:       653.49 MB/s
                  5227.94 Mb/s
Cycles per byte:  3.53
------------------------
Data size:        1048576 bytes
Iterations:       30
Time per run:     0.001196 seconds
Throughput:       836.20 MB/s
                  6689.60 Mb/s
Cycles per byte:  2.76
------------------------
Data size:        10485760 bytes
Iterations:       30
Time per run:     0.013443 seconds
Throughput:       743.89 MB/s
                  5951.10 Mb/s
Cycles per byte:  3.10
------------------------
Data size:        104857600 bytes
Iterations:       30
Time per run:     0.142959 seconds
Throughput:       699.50 MB/s
                  5596.01 Mb/s
Cycles per byte:  3.30
------------------------
```

These figures demonstrate competitive throughput on modern CPUs.

## License

This project is licensed under the **GNU Affero General Public License (AGPL), version 3** (or later).  
You can find the full text in the [LICENSE](./LICENSE) file.  

Under the AGPL, you are free to redistribute and modify this software as long as you:
- Provide notice of any modifications.
- Disclose source code if you run it as a network-accessible service.

For more details, please see [GNU AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html).

## Contributing

Bug reports, fixes, and improvements are welcome!  
Please open an issue or create a pull request on this GitHub repository.

## References

- **RFC 7008**: [KCipher-2](https://tools.ietf.org/html/rfc7008)  
- **CRYPTREC**: [Specification Documents](https://cryptrec.go.jp/en/cryptrec_13_spec_cypherlist_files/PDF/21_09spec_e_1.2.pdf)

---

**Disclaimer**:  
This software is provided **"as is"**, without warranty of any kind, express or implied.  
It is your responsibility to ensure the appropriateness of this cipher for your application and to validate security properties as required.

---