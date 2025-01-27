/**
 * @file cpu_cycles.h
 * @brief CPU cycle counter for x86/x64 and ARM platforms
 *
 * Copyright (c) 2025 Mounir IDRASSI <mounir@idrix.fr>
 *
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

/*
 * ----------------------------------------------------------------------------
 * NOTES:
 *
 * 1. x86/x64:
 *    - Uses CPUID + RDTSC/RDTSCP to provide some serialization. This helps
 *      reduce out-of-order execution effects. If RDTSCP is unavailable on
 *      older CPUs, fall back to RDTSC + CPUID.
 *    - TSC might not be truly invariant on older or mobile hardware (frequency
 *      scaling can affect it).
 *
 * 2. ARM (Windows on ARM64, Linux on AArch64, Apple Silicon):
 *    - Generally uses a hardware timer (e.g., CNTVCT_EL0, mach_absolute_time(),
 *      or QueryPerformanceCounter()). These may not literally count CPU cycles
 *      but do provide a high-resolution timestamp.
 *
 * 3. For truly rigorous benchmarking, consider:
 *    - Pinning the thread to one core (to avoid TSC desynchronization).
 *    - Disabling CPU frequency scaling if possible.
 *    - Inserting explicit serialization instructions around your measured code
 *      rather than (or in addition to) inside cpucycles().
 * ----------------------------------------------------------------------------
 */

#if defined(_WIN32) || defined(_WIN64)
 /* ------------------------------------------------------------------
    Windows
    ------------------------------------------------------------------ */
#  include <windows.h>
#  if defined(_M_IX86) || defined(_M_X64)
    /* ----------------------------------------
       Windows on x86/x64 uses __rdtsc or __rdtscp.
       RDTSCP is used by default. Define USE_RDTSC 
       to force using RDTSC instead.
       ---------------------------------------- */
#    include <intrin.h>

static inline uint64_t cpucycles(void)
{
#      ifndef USE_RDTSC
    unsigned int aux;
    /* Serialize + read TSC with RDTSCP */
    /* The RDTSCP instruction waits until all previous instructions have
       been executed before reading the TSC. */
    return __rdtscp(&aux);
#      else
    /* Fallback: CPUID + RDTSC */
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);           /* Serialize */
    return __rdtsc();
#      endif
}

#  elif defined(_M_ARM64)
    /*
     * Windows on ARM64 does not usually allow direct user-space access
     * to a hardware cycle counter. We fall back to QueryPerformanceCounter().
     * NOTE: QPC is a time-based counter, not a raw CPU cycle count.
     */
static inline uint64_t cpucycles(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint64_t)t.QuadPart;
}

#  else
#    error "Unsupported Windows architecture."
#  endif

#elif defined(__APPLE__)
 /* ------------------------------------------------------------------
    Apple (macOS on Intel or Apple Silicon)
    ------------------------------------------------------------------ */
#  include <TargetConditionals.h>
#  if defined(TARGET_OS_MAC) && TARGET_OS_MAC
#    include <mach/mach_time.h>

#if defined(__i386__) || defined(__x86_64__)
    /*
     * On Intel macOS, we use RDTSCP by default.
     * Define USE_RDTSC to force using RDTSC instead.
     */
static inline uint64_t cpucycles(void)
{
    uint32_t eax, edx;
#         ifndef USE_RDTSC
    /* Default: RDTSCP */
    uint32_t aux;
    __asm__ __volatile__(
        "rdtscp\n\t"         /* rdtscp sets EDX:EAX */
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "cpuid\n\t"         /* serialize after */
        : "=r"(edx), "=r"(eax)
        :
        : "%rax", "%rbx", "%rcx", "%rdx"
    );
#         else
    /* Fallback: CPUID + RDTSC when explicitly requested */
    __asm__ __volatile__(
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(eax), "=d"(edx)
        : "a"(0)
        : "%rbx", "%rcx"
    );
#         endif
    return ((uint64_t)eax) | (((uint64_t)edx) << 32);
}

#elif defined(__arm64__) || defined(__aarch64__)
    /*
     * On Apple Silicon, user-space direct PMU access is disabled by default.
     * We use mach_absolute_time() for high-resolution timing. This is a
     * time-based counter, not a literal CPU cycle count.
     */
static inline uint64_t cpucycles(void)
{
    return mach_absolute_time();
}

#else
#       error "Unsupported Apple architecture."
#endif

#  else
#    error "Unknown Apple platform."
#  endif

#elif defined(__linux__)
 /* ------------------------------------------------------------------
    Linux (x86, x64, ARM64)
    ------------------------------------------------------------------ */
#  if defined(__i386__) || defined(__x86_64__)
static inline uint64_t cpucycles(void)
{
    uint32_t eax, edx;
#       ifndef USE_RDTSC
    /* Default: RDTSCP */
    uint32_t aux;
    __asm__ __volatile__(
        "rdtscp\n\t"         /* read TSC -> EDX:EAX */
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "cpuid\n\t"          /* serialize */
        : "=r"(edx), "=r"(eax)
        :
        : "%rax", "%rbx", "%rcx", "%rdx"
    );
#       else
    /* Fallback: CPUID + RDTSC when explicitly requested */
    __asm__ __volatile__(
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(eax), "=d"(edx)
        : "a"(0)
        : "%rbx", "%rcx"
    );
#       endif
    return ((uint64_t)eax) | (((uint64_t)edx) << 32);
}

#  elif defined(__aarch64__)
    /*
     * On Linux/ARM64, we can read CNTVCT_EL0 in user space if permitted by
     * the kernel. This is a timer-based counter incrementing at a fixed
     * rate (CNTFRQ_EL0), not literally CPU cycles.
     */
static inline uint64_t cpucycles(void)
{
    uint64_t cnt;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
}
#  else
#    error "Unsupported Linux architecture."
#  endif

#else
 /* ------------------------------------------------------------------
    Fallback / Unsupported OS
    ------------------------------------------------------------------ */
#  warning "No cycle/timer counter implementation for this platform/arch."
static inline uint64_t cpucycles(void)
{
    return 0; /* Fallback to 0 (dummy) */
}
#endif

/*
 * Optional helper: compute cycles (or timer ticks) per byte.
 * Provide total cycles (end - start) and 'num_bytes' from your operation.
 *
 * NOTE: On many platforms this is not truly "cycles per byte" if the
 * counter is time-based (ARM64, Apple Silicon, Windows ARM64).
 */
static inline double cpucycles_per_byte(uint64_t cycles, size_t num_bytes)
{
    if (num_bytes == 0) {
        return 0.0;
    }
    return (double)cycles / (double)num_bytes;
}

