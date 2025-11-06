/*
 * ISC License
 *
 * Copyright (c) 2017-2024
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "hydrogen.h"

// ----------------------------------------------------------------------------------------------------------

#if defined(__linux__) && defined(__KERNEL__)
#    define TLS           /* Danger: at most one call into hydro_*() at a time */
#    define CHAR_BIT      8
#    define abort         BUG
#    define uint_fast16_t uint16_t
#    define errno         hydro_errno
static int errno;
#else
#    include <errno.h>
#    include <limits.h>
#    include <stdbool.h>
#    include <stdint.h>
#    include <stdlib.h>
#    include <string.h>
#endif

#if defined (__CHERIOT__)
static int errno;
#endif

#if !defined(__unix__) && (defined(__APPLE__) || defined(__linux__))
#    define __unix__ 1
#endif
#ifndef __GNUC__
#    define __restrict__
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define NATIVE_BIG_ENDIAN
#endif
#ifndef NATIVE_BIG_ENDIAN
#    ifndef NATIVE_LITTLE_ENDIAN
#        define NATIVE_LITTLE_ENDIAN
#    endif
#endif

#ifndef TLS
#    if defined(_WIN32) && !defined(__GNUC__)
#        define TLS __declspec(thread)
#    elif (defined(__clang__) || defined(__GNUC__)) && defined(__unix__) && !defined(__TINYC__)
#        define TLS __thread
#    else
#        define TLS
#    endif
#endif

#ifndef SIZE_MAX
#    define SIZE_MAX ((size_t) -1)
#endif

#ifdef __OpenBSD__
#    define HAVE_EXPLICIT_BZERO 1
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ) && defined(_GNU_SOURCE)
#    if __GLIBC_PREREQ(2, 25)
#        define HAVE_EXPLICIT_BZERO 1
#    endif
#endif

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#define ROTL32(x, b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))
#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define ROTR32(x, b) (uint32_t)(((x) >> (b)) | ((x) << (32 - (b))))
#define ROTR64(x, b) (uint64_t)(((x) >> (b)) | ((x) << (64 - (b))))

#define LOAD64_LE(SRC) load64_le(SRC)
static inline uint64_t
load64_le(const uint8_t src[8])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] << 8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void
store64_le(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[4] = (uint8_t) w;
    w >>= 8;
    dst[5] = (uint8_t) w;
    w >>= 8;
    dst[6] = (uint8_t) w;
    w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] << 8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

#define LOAD16_LE(SRC) load16_le(SRC)
static inline uint16_t
load16_le(const uint8_t src[2])
{
#ifdef NATIVE_LITTLE_ENDIAN
    uint16_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint16_t w = (uint16_t) src[0];
    w |= (uint16_t) src[1] << 8;
    return w;
#endif
}

#define STORE16_LE(DST, W) store16_le((DST), (W))
static inline void
store16_le(uint8_t dst[2], uint16_t w)
{
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
#endif
}

/* ----- */

#define LOAD64_BE(SRC) load64_be(SRC)
static inline uint64_t
load64_be(const uint8_t src[8])
{
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] << 8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
#endif
}

#define STORE64_BE(DST, W) store64_be((DST), (W))
static inline void
store64_be(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[7] = (uint8_t) w;
    w >>= 8;
    dst[6] = (uint8_t) w;
    w >>= 8;
    dst[5] = (uint8_t) w;
    w >>= 8;
    dst[4] = (uint8_t) w;
    w >>= 8;
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

#define LOAD32_BE(SRC) load32_be(SRC)
static inline uint32_t
load32_be(const uint8_t src[4])
{
#ifdef NATIVE_BIG_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] << 8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
#endif
}

#define STORE32_BE(DST, W) store32_be((DST), (W))
static inline void
store32_be(uint8_t dst[4], uint32_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[3] = (uint8_t) w;
    w >>= 8;
    dst[2] = (uint8_t) w;
    w >>= 8;
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

#define LOAD16_BE(SRC) load16_be(SRC)
static inline uint16_t
load16_be(const uint8_t src[2])
{
#ifdef NATIVE_BIG_ENDIAN
    uint16_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint16_t w = (uint16_t) src[1];
    w |= (uint16_t) src[0] << 8;
    return w;
#endif
}

#define STORE16_BE(DST, W) store16_be((DST), (W))
static inline void
store16_be(uint8_t dst[2], uint16_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

static inline void
mem_cpy(void *__restrict__ dst_, const void *__restrict__ src_, size_t n)
{
    unsigned char       *dst = (unsigned char *) dst_;
    const unsigned char *src = (const unsigned char *) src_;
    size_t               i;

    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static inline void
mem_zero(void *dst_, size_t n)
{
    unsigned char *dst = (unsigned char *) dst_;
    size_t         i;

    for (i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

static inline void
mem_xor(void *__restrict__ dst_, const void *__restrict__ src_, size_t n)
{
    unsigned char       *dst = (unsigned char *) dst_;
    const unsigned char *src = (const unsigned char *) src_;
    size_t               i;

    for (i = 0; i < n; i++) {
        dst[i] ^= src[i];
    }
}

static inline void
mem_xor2(void *__restrict__ dst_, const void *__restrict__ src1_, const void *__restrict__ src2_,
         size_t n)
{
    unsigned char       *dst  = (unsigned char *) dst_;
    const unsigned char *src1 = (const unsigned char *) src1_;
    const unsigned char *src2 = (const unsigned char *) src2_;
    size_t               i;

    for (i = 0; i < n; i++) {
        dst[i] = src1[i] ^ src2[i];
    }
}

static const uint8_t zero[64] = { 0 };

// ----------------------------------------------------------------------------------------------------------

static int hydro_random_init(void);

/* ---------------- */

#define gimli_BLOCKBYTES 48
#define gimli_CAPACITY   32
#define gimli_RATE       16

#define gimli_TAG_HEADER  0x01
#define gimli_TAG_PAYLOAD 0x02
#define gimli_TAG_FINAL   0x08
#define gimli_TAG_FINAL0  0xf8
#define gimli_TAG_KEY0    0xfe
#define gimli_TAG_KEY     0xff

#define gimli_DOMAIN_AEAD 0x0
#define gimli_DOMAIN_XOF  0xf

static void gimli_core_u8(uint8_t state_u8[gimli_BLOCKBYTES], uint8_t tag);

static inline void
gimli_pad_u8(uint8_t buf[gimli_BLOCKBYTES], size_t pos, uint8_t domain)
{
    buf[pos] ^= (domain << 1) | 1;
    buf[gimli_RATE - 1] ^= 0x80;
}

static inline void
hydro_mem_ct_zero_u32(uint32_t *dst_, size_t n)
{
    volatile uint32_t *volatile dst = (volatile uint32_t *volatile) (void *) dst_;
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

static inline uint32_t hydro_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2,
                                            size_t n) _hydro_attr_warn_unused_result_;

static inline uint32_t
hydro_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2, size_t n)
{
    const volatile uint32_t *volatile b1 = (const volatile uint32_t *volatile) (const void *) b1_;
    size_t   i;
    uint32_t cv = 0;

    for (i = 0; i < n; i++) {
        cv |= b1[i] ^ b2[i];
    }
    return cv;
}

/* ---------------- */

static int hydro_hash_init_with_tweak(hydro_hash_state *state,
                                      const char ctx[hydro_hash_CONTEXTBYTES], uint64_t tweak,
                                      const uint8_t key[hydro_hash_KEYBYTES]);

/* ---------------- */

#define hydro_secretbox_NONCEBYTES 20
#define hydro_secretbox_MACBYTES   16

/* ---------------- */

#define hydro_x25519_BYTES          32
#define hydro_x25519_PUBLICKEYBYTES 32
#define hydro_x25519_SECRETKEYBYTES 32

static int hydro_x25519_scalarmult(uint8_t       out[hydro_x25519_BYTES],
                                   const uint8_t scalar[hydro_x25519_SECRETKEYBYTES],
                                   const uint8_t x1[hydro_x25519_PUBLICKEYBYTES],
                                   bool          clamp) _hydro_attr_warn_unused_result_;

static inline int hydro_x25519_scalarmult_base(uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
                                               const uint8_t sk[hydro_x25519_SECRETKEYBYTES])
    _hydro_attr_warn_unused_result_;

static inline void
hydro_x25519_scalarmult_base_uniform(uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
                                     const uint8_t sk[hydro_x25519_SECRETKEYBYTES]);

// ----------------------------------------------------------------------------------------------------------

static TLS struct {
    _hydro_attr_aligned_(16) uint8_t state[gimli_BLOCKBYTES];
    uint64_t counter;
    uint8_t  initialized;
    uint8_t  available;
} hydro_random_context;

#if defined(AVR) && !defined(__unix__)

    #include <Arduino.h>

    static bool
    hydro_random_rbit(uint16_t x)
    {
        uint8_t x8;

        x8 = ((uint8_t) (x >> 8)) ^ (uint8_t) x;
        x8 = (x8 >> 4) ^ (x8 & 0xf);
        x8 = (x8 >> 2) ^ (x8 & 0x3);
        x8 = (x8 >> 1) ^ x8;

        return (bool) (x8 & 1);
    }

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;
        uint16_t         tc;
        bool             a, b;

        cli();
        MCUSR = 0;
        WDTCSR |= _BV(WDCE) | _BV(WDE);
        WDTCSR = _BV(WDIE);
        sei();

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            delay(1);
            tc = TCNT1;
            hydro_hash_update(&st, (const uint8_t *) &tc, sizeof tc);
            a = hydro_random_rbit(tc);
            delay(1);
            tc = TCNT1;
            b  = hydro_random_rbit(tc);
            hydro_hash_update(&st, (const uint8_t *) &tc, sizeof tc);
            if (a == b) {
                continue;
            }
            hydro_hash_update(&st, (const uint8_t *) &b, sizeof b);
            ebits++;
        }

        cli();
        MCUSR = 0;
        WDTCSR |= _BV(WDCE) | _BV(WDE);
        WDTCSR = 0;
        sei();

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

    ISR(WDT_vect)
    {
    }

#elif (defined(ESP32) || defined(ESP8266)) && !defined(__unix__)

    // Important: RF *must* be activated on ESP board
    // https://techtutorialsx.com/2017/12/22/esp32-arduino-random-number-generation/
    #ifdef ESP32
    #    include <esp_system.h>
    #endif

    #ifdef ARDUINO
    #    include <Arduino.h>
    #endif

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            uint32_t r = esp_random();

            delay(10);
            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

    #elif defined(PARTICLE) && defined(PLATFORM_ID) && PLATFORM_ID > 2 && !defined(__unix__)

    // Note: All particle platforms except for the Spark Core have a HW RNG.  Only allow building on
    // supported platforms for now. PLATFORM_ID definitions:
    // https://github.com/particle-iot/device-os/blob/mesh-develop/hal/shared/platforms.h

    #include <Particle.h>

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            uint32_t r = HAL_RNG_GetRandomNumber();
            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

#elif defined(__ZEPHYR__)

    #include <zephyr/random/rand32.h>

    static int
    hydro_random_init(void)
    {
        if (sys_csrand_get(&hydro_random_context.state, sizeof hydro_random_context.state) != 0) {
            return -1;
        }
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif (defined(NRF52832_XXAA) || defined(NRF52832_XXAB)) && !defined(__unix__)

    // Important: The SoftDevice *must* be activated to enable reading from the RNG
    // http://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.nrf52832.ps.v1.1%2Frng.html

    #include <nrf_soc.h>

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        const uint8_t    total_bytes     = 32;
        uint8_t          remaining_bytes = total_bytes;
        uint8_t          available_bytes;
        uint8_t          rand_buffer[32];

        hydro_hash_init(&st, ctx, NULL);

        for (;;) {
            if (sd_rand_application_bytes_available_get(&available_bytes) != NRF_SUCCESS) {
                return -1;
            }
            if (available_bytes > 0) {
                if (available_bytes > remaining_bytes) {
                    available_bytes = remaining_bytes;
                }
                if (sd_rand_application_vector_get(rand_buffer, available_bytes) != NRF_SUCCESS) {
                    return -1;
                }
                hydro_hash_update(&st, rand_buffer, total_bytes);
                remaining_bytes -= available_bytes;
            }
            if (remaining_bytes <= 0) {
                break;
            }
            delay(10);
        }
        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif defined(_WIN32)

    #include <windows.h>
    #define RtlGenRandom SystemFunction036
    #if defined(__cplusplus)
    extern "C"
    #endif
        BOOLEAN NTAPI
        RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
    #pragma comment(lib, "advapi32.lib")

    static int
    hydro_random_init(void)
    {
        if (!RtlGenRandom((PVOID) hydro_random_context.state,
                          (ULONG) sizeof hydro_random_context.state)) {
            return -1;
        }
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif defined(__wasi__)

    #include <unistd.h>

    static int
    hydro_random_init(void)
    {
        if (getentropy(hydro_random_context.state, sizeof hydro_random_context.state) != 0) {
            return -1;
        }
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif defined(__linux__) && defined(__KERNEL__)

    static int
    hydro_random_init(void)
    {
        get_random_bytes(&hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif defined(__unix__)

    #include <errno.h>
    #include <fcntl.h>
    #ifdef __linux__
    #    include <poll.h>
    #endif
    #include <sys/types.h>
    #include <unistd.h>

    #ifdef __linux__
    static int
    hydro_random_block_on_dev_random(void)
    {
        struct pollfd pfd;
        int           fd;
        int           pret;

        fd = open("/dev/random", O_RDONLY);
        if (fd == -1) {
            return 0;
        }
        pfd.fd      = fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;
        do {
            pret = poll(&pfd, 1, -1);
        } while (pret < 0 && (errno == EINTR || errno == EAGAIN));
        if (pret != 1) {
            (void) close(fd);
            errno = EIO;
            return -1;
        }
        return close(fd);
    }
    #endif

    static ssize_t
    hydro_random_safe_read(const int fd, void *const buf_, size_t len)
    {
        unsigned char *buf = (unsigned char *) buf_;
        ssize_t        readnb;

        do {
            while ((readnb = read(fd, buf, len)) < (ssize_t) 0 && (errno == EINTR || errno == EAGAIN)) {
            }
            if (readnb < (ssize_t) 0) {
                return readnb;
            }
            if (readnb == (ssize_t) 0) {
                break;
            }
            len -= (size_t) readnb;
            buf += readnb;
        } while (len > (ssize_t) 0);

        return (ssize_t) (buf - (unsigned char *) buf_);
    }

    static int
    hydro_random_init(void)
    {
        uint8_t tmp[gimli_BLOCKBYTES + 8];
        int     fd;
        int     ret = -1;

    #ifdef __linux__
        if (hydro_random_block_on_dev_random() != 0) {
            return -1;
        }
    #endif
        do {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd == -1 && errno != EINTR) {
                return -1;
            }
        } while (fd == -1);
        if (hydro_random_safe_read(fd, tmp, sizeof tmp) == (ssize_t) sizeof tmp) {
            memcpy(hydro_random_context.state, tmp, gimli_BLOCKBYTES);
            memcpy(&hydro_random_context.counter, tmp + gimli_BLOCKBYTES, 8);
            hydro_memzero(tmp, sizeof tmp);
            ret = 0;
        }
        ret |= close(fd);

        return ret;
    }

#elif defined(TARGET_LIKE_MBED)

    #include <mbedtls/ctr_drbg.h>
    #include <mbedtls/entropy.h>

    #if defined(MBEDTLS_ENTROPY_C)

    static int
    hydro_random_init(void)
    {
        mbedtls_entropy_context entropy;
        uint16_t                pos = 0;

        mbedtls_entropy_init(&entropy);

        // Pull data directly out of the entropy pool for the state, as it's small enough.
        if (mbedtls_entropy_func(&entropy, (uint8_t *) &hydro_random_context.counter,
                                 sizeof hydro_random_context.counter) != 0) {
            return -1;
        }
        // mbedtls_entropy_func can't provide more than MBEDTLS_ENTROPY_BLOCK_SIZE in one go.
        // This constant depends of mbedTLS configuration (whether the PRNG is backed by SHA256/SHA512
        // at this time) Therefore, if necessary, we get entropy multiple times.

        do {
            const uint8_t dataLeftToConsume = gimli_BLOCKBYTES - pos;
            const uint8_t currentChunkSize  = (dataLeftToConsume > MBEDTLS_ENTROPY_BLOCK_SIZE)
                                                  ? MBEDTLS_ENTROPY_BLOCK_SIZE
                                                  : dataLeftToConsume;

            // Forces mbedTLS to fetch fresh entropy, then get some to feed libhydrogen.
            if (mbedtls_entropy_gather(&entropy) != 0 ||
                mbedtls_entropy_func(&entropy, &hydro_random_context.state[pos], currentChunkSize) !=
                    0) {
                return -1;
            }
            pos += MBEDTLS_ENTROPY_BLOCK_SIZE;
        } while (pos < gimli_BLOCKBYTES);

        mbedtls_entropy_free(&entropy);

        return 0;
    }
    #else
    #    error Need an entropy source
    #endif

#elif defined(RIOT_VERSION)

    #include <random.h>

    static int
    hydro_random_init(void)
    {
        random_bytes(hydro_random_context.state, sizeof(hydro_random_context.state));
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);
        return 0;
    }

#elif defined(STM32F4) || defined(STM32L4)

    // Use hardware RNG peripheral
    // Working with HAL, LL Driver (untested)
    #if defined(STM32F4) || defined(STM32L4)

    #if defined(STM32F4)
    #include "stm32f4xx.h"
    #elif defined(STM32L4)
    #include "stm32l4xx_hal_rng.h"

    static RNG_HandleTypeDef RngHandle;
    #endif

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        __IO uint32_t tmpreg;

    #if defined(STM32F4)
        // Enable RNG clock source
        SET_BIT(RCC->AHB2ENR, RCC_AHB2ENR_RNGEN);

        // Delay after an RCC peripheral clock enabling
        tmpreg = READ_BIT(RCC->AHB2ENR, RCC_AHB2ENR_RNGEN);
        UNUSED(tmpreg);

        // RNG Peripheral enable
        SET_BIT(RNG->CR, RNG_CR_RNGEN);
    #elif defined(STM32L4)
        RngHandle.Instance = RNG;
        HAL_RNG_Init(&RngHandle);
    #endif

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            uint32_t r = 0;
    #if defined(STM32F4)
            while (!(READ_BIT(RNG->SR, RNG_SR_DRDY))) {
            }

            r = RNG->DR;
    #elif defined(STM32L4)
            if (HAL_RNG_GenerateRandomNumber(&RngHandle, &r) != HAL_OK) {
                continue;
            }
    #endif
            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }
    #else
    #error SMT32 implementation missing!
    #endif

#elif defined(__RTTHREAD__)

    #include <hw_rng.h>
    #include <rtthread.h>

    #define DBG_TAG "libhydrogen"
    #define DBG_LVL DBG_LOG
    #include <rtdbg.h>

    static int
    hydrogen_init(void)
    {
        if (hydro_init() != 0) {
            abort();
        }
        LOG_I("libhydrogen initialized");
        return 0;
    }
    INIT_APP_EXPORT(hydrogen_init);

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            uint32_t r = rt_hwcrypto_rng_update();
            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

#elif defined(CH32V30x_D8) || defined(CH32V30x_D8C)

    #if defined(CH32V30x_D8) || defined(CH32V30x_D8C)
    #    include <ch32v30x_rng.h>
    #else
    #    error CH32 implementation missing!
    #endif

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        // Enable RNG clock source
        RCC_AHBPeriphClockCmd(RCC_AHBPeriph_RNG, ENABLE);

        // RNG Peripheral enable
        RNG_Cmd(ENABLE);

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET)
                ;
            uint32_t r = RNG_GetRandomNumber();

            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

#elif defined(CHIBIOS)

    #include <stdbool.h>
    #include <stddef.h>
    #include <stdint.h>

    /* Declarations from ChibiOS HAL TRNG module */

    extern struct hal_trng_driver TRNGD1;

    void trngStart(struct hal_trng_driver *, const void *);
    bool trngGenerate(struct hal_trng_driver *, size_t size, uint8_t *);

    static int
    hydro_random_init(void)
    {
        trngStart(&TRNGD1, NULL);

        if (trngGenerate(&TRNGD1, sizeof hydro_random_context.state, hydro_random_context.state)) {
            return -1;
        }
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }

#elif defined(__CHERIOT__)

    uint32_t rand_32();

    static int
    hydro_random_init(void)
    {
        const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
        hydro_hash_state st;
        uint16_t         ebits = 0;

        hydro_hash_init(&st, ctx, NULL);

        while (ebits < 256) {
            uint32_t r = rand_32();
            hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
            ebits += 32;
        }

        hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
        hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

        return 0;
    }
    
#else

    #error Unsupported platform

#endif

static void
hydro_random_ensure_initialized(void)
{
    if (hydro_random_context.initialized == 0) {
        if (hydro_random_init() != 0) {
            abort();
        }
        gimli_core_u8(hydro_random_context.state, 0);
        hydro_random_ratchet();
        hydro_random_context.initialized = 1;
    }
}

void
hydro_random_ratchet(void)
{
    mem_zero(hydro_random_context.state, gimli_RATE);
    STORE64_LE(hydro_random_context.state, hydro_random_context.counter);
    hydro_random_context.counter++;
    gimli_core_u8(hydro_random_context.state, 0);
    hydro_random_context.available = gimli_RATE;
}

uint32_t
hydro_random_u32(void)
{
    uint32_t v;

    hydro_random_ensure_initialized();
    if (hydro_random_context.available < 4) {
        hydro_random_ratchet();
    }
    memcpy(&v, &hydro_random_context.state[gimli_RATE - hydro_random_context.available], 4);
    hydro_random_context.available -= 4;

    return v;
}

uint32_t
hydro_random_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2U) {
        return 0;
    }
    min = (1U + ~upper_bound) % upper_bound; /* = 2**32 mod upper_bound */
    do {
        r = hydro_random_u32();
    } while (r < min);
    /* r is now clamped to a set whose size mod upper_bound == 0
     * the worst case (2**31+1) requires 2 attempts on average */

    return r % upper_bound;
}

void
hydro_random_buf(void *out, size_t out_len)
{
    uint8_t *p = (uint8_t *) out;
    size_t   i;
    size_t   leftover;

    hydro_random_ensure_initialized();
    for (i = 0; i < out_len / gimli_RATE; i++) {
        gimli_core_u8(hydro_random_context.state, 0);
        memcpy(p + i * gimli_RATE, hydro_random_context.state, gimli_RATE);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        gimli_core_u8(hydro_random_context.state, 0);
        mem_cpy(p + i * gimli_RATE, hydro_random_context.state, leftover);
    }
    hydro_random_ratchet();
}

void
hydro_random_buf_deterministic(void *out, size_t out_len,
                               const uint8_t seed[hydro_random_SEEDBYTES])
{
    static const uint8_t             prefix[] = { 7, 'd', 'r', 'b', 'g', '2', '5', '6' };
    _hydro_attr_aligned_(16) uint8_t state[gimli_BLOCKBYTES];
    uint8_t                         *p = (uint8_t *) out;
    size_t                           i;
    size_t                           leftover;

    mem_zero(state, gimli_BLOCKBYTES);
    COMPILER_ASSERT(sizeof prefix + 8 <= gimli_RATE);
    memcpy(state, prefix, sizeof prefix);
    STORE64_LE(state + sizeof prefix, (uint64_t) out_len);
    gimli_core_u8(state, 1);
    COMPILER_ASSERT(hydro_random_SEEDBYTES == gimli_RATE * 2);
    mem_xor(state, seed, gimli_RATE);
    gimli_core_u8(state, 2);
    mem_xor(state, seed + gimli_RATE, gimli_RATE);
    gimli_core_u8(state, 2);
    for (i = 0; i < out_len / gimli_RATE; i++) {
        gimli_core_u8(state, 0);
        memcpy(p + i * gimli_RATE, state, gimli_RATE);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        gimli_core_u8(state, 0);
        mem_cpy(p + i * gimli_RATE, state, leftover);
    }
}

void
hydro_random_reseed(void)
{
    hydro_random_context.initialized = 0;
    hydro_random_ensure_initialized();
}

// ----------------------------------------------------------------------------------------------------------

int
hydro_init(void)
{
    hydro_random_ensure_initialized();
    return 0;
}

void
hydro_memzero(void *pnt, size_t len)
{
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(pnt, len);
#else
    volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile) pnt;
    size_t i                              = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}

void
hydro_increment(uint8_t *n, size_t len)
{
    size_t        i;
    uint_fast16_t c = 1U;

    for (i = 0; i < len; i++) {
        c += (uint_fast16_t) n[i];
        n[i] = (uint8_t) c;
        c >>= 8;
    }
}

char *
hydro_bin2hex(char *hex, size_t hex_maxlen, const uint8_t *bin, size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        abort();
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0U;

    return hex;
}

int
hydro_hex2bin(uint8_t *bin, size_t bin_maxlen, const char *hex, size_t hex_len, const char *ignore,
              const char **hex_end_p)
{
    size_t        bin_pos = (size_t) 0U;
    size_t        hex_pos = (size_t) 0U;
    int           ret     = 0;
    unsigned char c;
    unsigned char c_alpha0, c_alpha;
    unsigned char c_num0, c_num;
    uint8_t       c_acc = 0U;
    uint8_t       c_val;
    unsigned char state = 0U;

    while (hex_pos < hex_len) {
        c        = (unsigned char) hex[hex_pos];
        c_num    = c ^ 48U;
        c_num0   = (c_num - 10U) >> 8;
        c_alpha  = (c & ~32U) - 55U;
        c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
        if ((c_num0 | c_alpha0) == 0U) {
            if (ignore != NULL && state == 0U && strchr(ignore, c) != NULL) {
                hex_pos++;
                continue;
            }
            break;
        }
        c_val = (uint8_t) ((c_num0 & c_num) | (c_alpha0 & c_alpha));
        if (bin_pos >= bin_maxlen) {
            ret   = -1;
            errno = ERANGE;
            break;
        }
        if (state == 0U) {
            c_acc = c_val * 16U;
        } else {
            bin[bin_pos++] = c_acc | c_val;
        }
        state = ~state;
        hex_pos++;
    }
    if (state != 0U) {
        hex_pos--;
        errno = EINVAL;
        ret   = -1;
    }
    if (ret != 0) {
        bin_pos = (size_t) 0U;
    }
    if (hex_end_p != NULL) {
        *hex_end_p = &hex[hex_pos];
    } else if (hex_pos != hex_len) {
        errno = EINVAL;
        ret   = -1;
    }
    if (ret != 0) {
        return ret;
    }
    return (int) bin_pos;
}

bool
hydro_equal(const void *b1_, const void *b2_, size_t len)
{
    const volatile uint8_t *volatile b1 = (const volatile uint8_t *volatile) b1_;
    const uint8_t *b2                   = (const uint8_t *) b2_;
    size_t         i;
    uint8_t        d = (uint8_t) 0U;

    if (b1 == b2) {
        d = ~d;
    }
    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (bool) (1 & ((d - 1) >> 8));
}

int
hydro_compare(const uint8_t *b1_, const uint8_t *b2_, size_t len)
{
    const volatile uint8_t *volatile b1 = (const volatile uint8_t *volatile) b1_;
    const uint8_t *b2                   = (const uint8_t *) b2_;
    uint8_t        gt                   = 0U;
    uint8_t        eq                   = 1U;
    size_t         i;

    i = len;
    while (i != 0U) {
        i--;
        gt |= ((b2[i] - b1[i]) >> 8) & eq;
        eq &= ((b2[i] ^ b1[i]) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}

int
hydro_pad(unsigned char *buf, size_t unpadded_buflen, size_t blocksize, size_t max_buflen)
{
    unsigned char         *tail;
    size_t                 i;
    size_t                 xpadlen;
    size_t                 xpadded_len;
    volatile unsigned char mask;
    unsigned char          barrier_mask;

    if (blocksize <= 0U || max_buflen > INT_MAX) {
        return -1;
    }
    xpadlen = blocksize - 1U;
    if ((blocksize & (blocksize - 1U)) == 0U) {
        xpadlen -= unpadded_buflen & (blocksize - 1U);
    } else {
        xpadlen -= unpadded_buflen % blocksize;
    }
    if ((size_t) SIZE_MAX - unpadded_buflen <= xpadlen) {
        return -1;
    }
    xpadded_len = unpadded_buflen + xpadlen;
    if (xpadded_len >= max_buflen) {
        return -1;
    }
    tail = &buf[xpadded_len];
    mask = 0U;
    for (i = 0; i < blocksize; i++) {
        barrier_mask = (unsigned char) (((i ^ xpadlen) - 1U) >> ((sizeof(size_t) - 1U) * CHAR_BIT));
        *(tail - i)  = ((*(tail - i)) & mask) | (0x80 & barrier_mask);
        mask |= barrier_mask;
    }
    return (int) (xpadded_len + 1);
}

int
hydro_unpad(const unsigned char *buf, size_t padded_buflen, size_t blocksize)
{
    const unsigned char *tail;
    unsigned char        acc = 0U;
    unsigned char        c;
    unsigned char        valid   = 0U;
    volatile size_t      pad_len = 0U;
    size_t               i;
    size_t               is_barrier;

    if (padded_buflen < blocksize || blocksize <= 0U) {
        return -1;
    }
    tail = &buf[padded_buflen - 1U];

    for (i = 0U; i < blocksize; i++) {
        c          = *(tail - i);
        is_barrier = (((acc - 1U) & (pad_len - 1U) & ((c ^ 0x80) - 1U)) >> 8) & 1U;
        acc |= c;
        pad_len |= i & (1U + ~is_barrier);
        valid |= (unsigned char) is_barrier;
    }
    if (valid == 0) {
        return -1;
    }
    return (int) (padded_buflen - 1 - pad_len);
}

// ----------------------------------------------------------------------------------------------------------

#ifdef __SSE2__

#include <emmintrin.h>
#ifdef __SSSE3__
#    include <tmmintrin.h>
#endif

#define S 9

static inline __m128i
shift(__m128i x, int bits)
{
    return _mm_slli_epi32(x, bits);
}

static inline __m128i
rotate(__m128i x, int bits)
{
    return _mm_slli_epi32(x, bits) | _mm_srli_epi32(x, 32 - bits);
}

#ifdef __SSSE3__
static inline __m128i
rotate24(__m128i x)
{
    return _mm_shuffle_epi8(x, _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1));
}
#else
static inline __m128i
rotate24(__m128i x)
{
    uint8_t _hydro_attr_aligned_(16) x8[16], y8[16];

    _mm_storeu_si128((__m128i *) (void *) x8, x);

    y8[0]  = x8[1];
    y8[1]  = x8[2];
    y8[2]  = x8[3];
    y8[3]  = x8[0];
    y8[4]  = x8[5];
    y8[5]  = x8[6];
    y8[6]  = x8[7];
    y8[7]  = x8[4];
    y8[8]  = x8[9];
    y8[9]  = x8[10];
    y8[10] = x8[11];
    y8[11] = x8[8];
    y8[12] = x8[13];
    y8[13] = x8[14];
    y8[14] = x8[15];
    y8[15] = x8[12];

    return _mm_loadu_si128((const __m128i *) (const void *) y8);
}
#endif

static const uint32_t _hydro_attr_aligned_(16) coeffs[24] = {
    0x9e377904, 0, 0, 0, 0x9e377908, 0, 0, 0, 0x9e37790c, 0, 0, 0,
    0x9e377910, 0, 0, 0, 0x9e377914, 0, 0, 0, 0x9e377918, 0, 0, 0,
};

static void
gimli_core(uint32_t state[gimli_BLOCKBYTES / 4])
{
    __m128i x = _mm_loadu_si128((const __m128i *) (const void *) &state[0]);
    __m128i y = _mm_loadu_si128((const __m128i *) (const void *) &state[4]);
    __m128i z = _mm_loadu_si128((const __m128i *) (const void *) &state[8]);
    __m128i newy;
    __m128i newz;
    int     round;

    for (round = 5; round >= 0; round--) {
        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x = _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
        x ^= ((const __m128i *) (const void *) coeffs)[round];

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x = _mm_shuffle_epi32(x, _MM_SHUFFLE(1, 0, 3, 2));

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;
    }

    _mm_storeu_si128((__m128i *) (void *) &state[0], x);
    _mm_storeu_si128((__m128i *) (void *) &state[4], y);
    _mm_storeu_si128((__m128i *) (void *) &state[8], z);
}

#else // #ifdef __SSE2__

static void
gimli_core(uint32_t state[gimli_BLOCKBYTES / 4])
{
    unsigned int round;
    unsigned int column;
    uint32_t     x;
    uint32_t     y;
    uint32_t     z;

    for (round = 24; round > 0; round--) {
        for (column = 0; column < 4; column++) {
            x = ROTL32(state[column], 24);
            y = ROTL32(state[4 + column], 9);
            z = state[8 + column];

            state[8 + column] = x ^ (z << 1) ^ ((y & z) << 2);
            state[4 + column] = y ^ x ^ ((x | z) << 1);
            state[column]     = z ^ y ^ ((x & y) << 3);
        }
        switch (round & 3) {
        case 0:
            x        = state[0];
            state[0] = state[1];
            state[1] = x;
            x        = state[2];
            state[2] = state[3];
            state[3] = x;
            state[0] ^= ((uint32_t) 0x9e377900 | round);
            break;
        case 2:
            x        = state[0];
            state[0] = state[2];
            state[2] = x;
            x        = state[1];
            state[1] = state[3];
            state[3] = x;
        }
    }
}

#endif // #ifdef __SSE2__

static void
gimli_core_u8(uint8_t state_u8[gimli_BLOCKBYTES], uint8_t tag)
{
    state_u8[gimli_BLOCKBYTES - 1] ^= tag;
#ifndef NATIVE_LITTLE_ENDIAN
    uint32_t state_u32[12];
    int      i;

    for (i = 0; i < 12; i++) {
        state_u32[i] = LOAD32_LE(&state_u8[i * 4]);
    }
    gimli_core(state_u32);
    for (i = 0; i < 12; i++) {
        STORE32_LE(&state_u8[i * 4], state_u32[i]);
    }
#else
    gimli_core((uint32_t *) (void *) state_u8); /* state_u8 must be properly aligned */
#endif
}

// ----------------------------------------------------------------------------------------------------------

int
hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len)
{
    const uint8_t *in  = (const uint8_t *) in_;
    uint8_t       *buf = (uint8_t *) (void *) state->state;
    size_t         left;
    size_t         ps;
    size_t         i;

    while (in_len > 0) {
        left = gimli_RATE - state->buf_off;
        if ((ps = in_len) > left) {
            ps = left;
        }
        for (i = 0; i < ps; i++) {
            buf[state->buf_off + i] ^= in[i];
        }
        in += ps;
        in_len -= ps;
        state->buf_off += (uint8_t) ps;
        if (state->buf_off == gimli_RATE) {
            gimli_core_u8(buf, 0);
            state->buf_off = 0;
        }
    }
    return 0;
}

/* pad(str_enc("kmac") || str_enc(context)) || pad(str_enc(k)) ||
   msg || right_enc(msg_len) || 0x00 */

int
hydro_hash_init(hydro_hash_state *state, const char ctx[hydro_hash_CONTEXTBYTES],
                const uint8_t key[hydro_hash_KEYBYTES])
{
    uint8_t block[64] = { 4, 'k', 'm', 'a', 'c', 8 };
    size_t  p;

    COMPILER_ASSERT(hydro_hash_KEYBYTES <= sizeof block - gimli_RATE - 1);
    COMPILER_ASSERT(hydro_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    memcpy(block + 6, ctx, 8);
    if (key != NULL) {
        block[gimli_RATE] = (uint8_t) hydro_hash_KEYBYTES;
        memcpy(block + gimli_RATE + 1, key, hydro_hash_KEYBYTES);
        p = (gimli_RATE + 1 + hydro_hash_KEYBYTES + (gimli_RATE - 1)) & ~(size_t) (gimli_RATE - 1);
    } else {
        block[gimli_RATE] = (uint8_t) 0;
        p                 = (gimli_RATE + 1 + 0 + (gimli_RATE - 1)) & ~(size_t) (gimli_RATE - 1);
    }
    mem_zero(state, sizeof *state);
    hydro_hash_update(state, block, p);

    return 0;
}

/* pad(str_enc("tmac") || str_enc(context)) || pad(str_enc(k)) ||
   pad(right_enc(tweak)) || msg || right_enc(msg_len) || 0x00 */

static int
hydro_hash_init_with_tweak(hydro_hash_state *state, const char ctx[hydro_hash_CONTEXTBYTES],
                           uint64_t tweak, const uint8_t key[hydro_hash_KEYBYTES])
{
    uint8_t block[80] = { 4, 't', 'm', 'a', 'c', 8 };
    size_t  p;

    COMPILER_ASSERT(hydro_hash_KEYBYTES <= sizeof block - 2 * gimli_RATE - 1);
    COMPILER_ASSERT(hydro_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    memcpy(block + 6, ctx, 8);
    if (key != NULL) {
        block[gimli_RATE] = (uint8_t) hydro_hash_KEYBYTES;
        memcpy(block + gimli_RATE + 1, key, hydro_hash_KEYBYTES);
        p = (gimli_RATE + 1 + hydro_hash_KEYBYTES + (gimli_RATE - 1)) & ~(size_t) (gimli_RATE - 1);
    } else {
        block[gimli_RATE] = (uint8_t) 0;
        p                 = (gimli_RATE + 1 + 0 + (gimli_RATE - 1)) & ~(size_t) (gimli_RATE - 1);
    }
    block[p] = (uint8_t) sizeof tweak;
    STORE64_LE(&block[p + 1], tweak);
    p += gimli_RATE;
    mem_zero(state, sizeof *state);
    hydro_hash_update(state, block, p);

    return 0;
}

int
hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len)
{
    uint8_t  lc[4];
    uint8_t *buf = (uint8_t *) (void *) state->state;
    size_t   i;
    size_t   lc_len;
    size_t   leftover;

    if (out_len < hydro_hash_BYTES_MIN || out_len > hydro_hash_BYTES_MAX) {
        return -1;
    }
    COMPILER_ASSERT(hydro_hash_BYTES_MAX <= 0xffff);
    lc[1]  = (uint8_t) out_len;
    lc[2]  = (uint8_t) (out_len >> 8);
    lc[3]  = 0;
    lc_len = (size_t) (1 + (lc[2] != 0));
    lc[0]  = (uint8_t) lc_len;
    hydro_hash_update(state, lc, 1 + lc_len + 1);
    gimli_pad_u8(buf, state->buf_off, gimli_DOMAIN_XOF);
    for (i = 0; i < out_len / gimli_RATE; i++) {
        gimli_core_u8(buf, 0);
        memcpy(out + i * gimli_RATE, buf, gimli_RATE);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        gimli_core_u8(buf, 0);
        mem_cpy(out + i * gimli_RATE, buf, leftover);
    }
    state->buf_off = gimli_RATE;

    return 0;
}

int
hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_, size_t in_len,
                const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t key[hydro_hash_KEYBYTES])
{
    hydro_hash_state st;
    const uint8_t   *in = (const uint8_t *) in_;

    if (hydro_hash_init(&st, ctx, key) != 0 || hydro_hash_update(&st, in, in_len) != 0 ||
        hydro_hash_final(&st, out, out_len) != 0) {
        return -1;
    }
    return 0;
}

void
hydro_hash_keygen(uint8_t key[hydro_hash_KEYBYTES])
{
    hydro_random_buf(key, hydro_hash_KEYBYTES);
}

// ----------------------------------------------------------------------------------------------------------

int
hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len, uint64_t subkey_id,
                          const char    ctx[hydro_kdf_CONTEXTBYTES],
                          const uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_hash_state st;

    COMPILER_ASSERT(hydro_kdf_CONTEXTBYTES >= hydro_hash_CONTEXTBYTES);
    COMPILER_ASSERT(hydro_kdf_KEYBYTES >= hydro_hash_KEYBYTES);
    if (hydro_hash_init_with_tweak(&st, ctx, subkey_id, key) != 0) {
        return -1;
    }
    return hydro_hash_final(&st, subkey, subkey_len);
}

void
hydro_kdf_keygen(uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_random_buf(key, hydro_kdf_KEYBYTES);
}

// ----------------------------------------------------------------------------------------------------------

#define hydro_secretbox_IVBYTES  20
#define hydro_secretbox_SIVBYTES 20
#define hydro_secretbox_MACBYTES 16

void
hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES])
{
    hydro_random_buf(key, hydro_secretbox_KEYBYTES);
}

static void
hydro_secretbox_xor_enc(uint8_t buf[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in,
                        size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        memcpy(buf, &out[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_cpy(buf, &out[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(buf, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(buf, gimli_TAG_PAYLOAD);
}

static void
hydro_secretbox_xor_dec(uint8_t buf[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in,
                        size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        memcpy(buf, &in[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_cpy(buf, &in[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(buf, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(buf, gimli_TAG_PAYLOAD);
}

static void
hydro_secretbox_setup(uint8_t buf[gimli_BLOCKBYTES], uint64_t msg_id,
                      const char    ctx[hydro_secretbox_CONTEXTBYTES],
                      const uint8_t key[hydro_secretbox_KEYBYTES],
                      const uint8_t iv[hydro_secretbox_IVBYTES], uint8_t key_tag)
{
    static const uint8_t prefix[] = { 6, 's', 'b', 'x', '2', '5', '6', 8 };
    uint8_t              msg_id_le[8];

    mem_zero(buf, gimli_BLOCKBYTES);
    COMPILER_ASSERT(hydro_secretbox_CONTEXTBYTES == 8);
    COMPILER_ASSERT(sizeof prefix + hydro_secretbox_CONTEXTBYTES <= gimli_RATE);
    memcpy(buf, prefix, sizeof prefix);
    memcpy(buf + sizeof prefix, ctx, hydro_secretbox_CONTEXTBYTES);
    COMPILER_ASSERT(sizeof prefix + hydro_secretbox_CONTEXTBYTES == gimli_RATE);
    gimli_core_u8(buf, gimli_TAG_HEADER);

    COMPILER_ASSERT(hydro_secretbox_KEYBYTES == 2 * gimli_RATE);
    mem_xor(buf, key, gimli_RATE);
    gimli_core_u8(buf, key_tag);
    mem_xor(buf, key + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf, key_tag);

    COMPILER_ASSERT(hydro_secretbox_IVBYTES < gimli_RATE * 2);
    buf[0] ^= hydro_secretbox_IVBYTES;
    mem_xor(&buf[1], iv, gimli_RATE - 1);
    gimli_core_u8(buf, gimli_TAG_HEADER);
    mem_xor(buf, iv + gimli_RATE - 1, hydro_secretbox_IVBYTES - (gimli_RATE - 1));
    STORE64_LE(msg_id_le, msg_id);
    COMPILER_ASSERT(hydro_secretbox_IVBYTES - gimli_RATE + 8 <= gimli_RATE);
    mem_xor(buf + hydro_secretbox_IVBYTES - gimli_RATE, msg_id_le, 8);
    gimli_core_u8(buf, gimli_TAG_HEADER);
}

static void
hydro_secretbox_final(uint8_t *buf, const uint8_t key[hydro_secretbox_KEYBYTES], uint8_t tag)
{
    COMPILER_ASSERT(hydro_secretbox_KEYBYTES == gimli_CAPACITY);
    mem_xor(buf + gimli_RATE, key, hydro_secretbox_KEYBYTES);
    gimli_core_u8(buf, tag);
    mem_xor(buf + gimli_RATE, key, hydro_secretbox_KEYBYTES);
    gimli_core_u8(buf, tag);
}

static int
hydro_secretbox_encrypt_iv(uint8_t *c, const void *m_, size_t mlen, uint64_t msg_id,
                           const char    ctx[hydro_secretbox_CONTEXTBYTES],
                           const uint8_t key[hydro_secretbox_KEYBYTES],
                           const uint8_t iv[hydro_secretbox_IVBYTES])
{
    _hydro_attr_aligned_(16) uint32_t state[gimli_BLOCKBYTES / 4];
    uint8_t                          *buf = (uint8_t *) (void *) state;
    const uint8_t                    *m   = (const uint8_t *) m_;
    uint8_t                          *siv = &c[0];
    uint8_t                          *mac = &c[hydro_secretbox_SIVBYTES];
    uint8_t                          *ct  = &c[hydro_secretbox_SIVBYTES + hydro_secretbox_MACBYTES];
    size_t                            i;
    size_t                            leftover;

    if (c == m) {
        memmove(c + hydro_secretbox_HEADERBYTES, m, mlen);
        m = c + hydro_secretbox_HEADERBYTES;
    }

    /* first pass: compute the SIV */

    hydro_secretbox_setup(buf, msg_id, ctx, key, iv, gimli_TAG_KEY0);
    for (i = 0; i < mlen / gimli_RATE; i++) {
        mem_xor(buf, &m[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_PAYLOAD);
    }
    leftover = mlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor(buf, &m[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(buf, leftover, gimli_DOMAIN_XOF);
    gimli_core_u8(buf, gimli_TAG_PAYLOAD);

    hydro_secretbox_final(buf, key, gimli_TAG_FINAL0);
    COMPILER_ASSERT(hydro_secretbox_SIVBYTES <= gimli_CAPACITY);
    memcpy(siv, buf + gimli_RATE, hydro_secretbox_SIVBYTES);

    /* second pass: encrypt the message, mix the key, squeeze an extra block for
     * the MAC */

    COMPILER_ASSERT(hydro_secretbox_SIVBYTES == hydro_secretbox_IVBYTES);
    hydro_secretbox_setup(buf, msg_id, ctx, key, siv, gimli_TAG_KEY);
    hydro_secretbox_xor_enc(buf, ct, m, mlen);

    hydro_secretbox_final(buf, key, gimli_TAG_FINAL);
    COMPILER_ASSERT(hydro_secretbox_MACBYTES <= gimli_CAPACITY);
    memcpy(mac, buf + gimli_RATE, hydro_secretbox_MACBYTES);

    return 0;
}

void
hydro_secretbox_probe_create(uint8_t probe[hydro_secretbox_PROBEBYTES], const uint8_t *c,
                             size_t c_len, const char ctx[hydro_secretbox_CONTEXTBYTES],
                             const uint8_t key[hydro_secretbox_KEYBYTES])
{
    const uint8_t *mac;

    if (c_len < hydro_secretbox_HEADERBYTES) {
        abort();
    }
    mac = &c[hydro_secretbox_SIVBYTES];
    COMPILER_ASSERT(hydro_secretbox_CONTEXTBYTES >= hydro_hash_CONTEXTBYTES);
    COMPILER_ASSERT(hydro_secretbox_KEYBYTES >= hydro_hash_KEYBYTES);
    hydro_hash_hash(probe, hydro_secretbox_PROBEBYTES, mac, hydro_secretbox_MACBYTES, ctx, key);
}

int
hydro_secretbox_probe_verify(const uint8_t probe[hydro_secretbox_PROBEBYTES], const uint8_t *c,
                             size_t c_len, const char ctx[hydro_secretbox_CONTEXTBYTES],
                             const uint8_t key[hydro_secretbox_KEYBYTES])
{
    uint8_t        computed_probe[hydro_secretbox_PROBEBYTES];
    const uint8_t *mac;

    if (c_len < hydro_secretbox_HEADERBYTES) {
        return -1;
    }
    mac = &c[hydro_secretbox_SIVBYTES];
    hydro_hash_hash(computed_probe, hydro_secretbox_PROBEBYTES, mac, hydro_secretbox_MACBYTES, ctx,
                    key);
    if (hydro_equal(computed_probe, probe, hydro_secretbox_PROBEBYTES) == 1) {
        return 0;
    }
    hydro_memzero(computed_probe, hydro_secretbox_PROBEBYTES);
    return -1;
}

int
hydro_secretbox_encrypt(uint8_t *c, const void *m_, size_t mlen, uint64_t msg_id,
                        const char    ctx[hydro_secretbox_CONTEXTBYTES],
                        const uint8_t key[hydro_secretbox_KEYBYTES])
{
    uint8_t iv[hydro_secretbox_IVBYTES];

    hydro_random_buf(iv, sizeof iv);

    return hydro_secretbox_encrypt_iv(c, m_, mlen, msg_id, ctx, key, iv);
}

int
hydro_secretbox_decrypt(void *m_, const uint8_t *c, size_t clen, uint64_t msg_id,
                        const char    ctx[hydro_secretbox_CONTEXTBYTES],
                        const uint8_t key[hydro_secretbox_KEYBYTES])
{
    _hydro_attr_aligned_(16) uint32_t state[gimli_BLOCKBYTES / 4];
    uint32_t                          pub_mac[hydro_secretbox_MACBYTES / 4];
    uint8_t                          *buf = (uint8_t *) (void *) state;
    const uint8_t                    *siv;
    const uint8_t                    *mac;
    const uint8_t                    *ct;
    uint8_t                          *m = (uint8_t *) m_;
    size_t                            mlen;
    uint32_t                          cv;

    if (clen < hydro_secretbox_HEADERBYTES) {
        return -1;
    }
    siv = &c[0];
    mac = &c[hydro_secretbox_SIVBYTES];
    ct  = &c[hydro_secretbox_SIVBYTES + hydro_secretbox_MACBYTES];

    mlen = clen - hydro_secretbox_HEADERBYTES;
    memcpy(pub_mac, mac, sizeof pub_mac);
    COMPILER_ASSERT(hydro_secretbox_SIVBYTES == hydro_secretbox_IVBYTES);
    hydro_secretbox_setup(buf, msg_id, ctx, key, siv, gimli_TAG_KEY);
    hydro_secretbox_xor_dec(buf, m, ct, mlen);

    hydro_secretbox_final(buf, key, gimli_TAG_FINAL);
    COMPILER_ASSERT(hydro_secretbox_MACBYTES <= gimli_CAPACITY);
    COMPILER_ASSERT(gimli_RATE % 4 == 0);
    cv = hydro_mem_ct_cmp_u32(state + gimli_RATE / 4, pub_mac, hydro_secretbox_MACBYTES / 4);
    hydro_mem_ct_zero_u32(state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}

// ----------------------------------------------------------------------------------------------------------

/*
 * Based on Michael Hamburg's STROBE reference implementation.
 * Copyright (c) 2015-2016 Cryptography Research, Inc.
 * MIT License (MIT)
 */

#if defined(__GNUC__) && defined(__SIZEOF_INT128__)
#    define hydro_x25519_WBITS 64
#else
#    define hydro_x25519_WBITS 32
#endif

#if hydro_x25519_WBITS == 64
typedef uint64_t    hydro_x25519_limb_t;
typedef __uint128_t hydro_x25519_dlimb_t;
typedef __int128_t  hydro_x25519_sdlimb_t;
#    define hydro_x25519_eswap_limb(X) LOAD64_LE((const uint8_t *) &(X))
#    define hydro_x25519_LIMB(x)       x##ull
#elif hydro_x25519_WBITS == 32
typedef uint32_t hydro_x25519_limb_t;
typedef uint64_t hydro_x25519_dlimb_t;
typedef int64_t  hydro_x25519_sdlimb_t;
#    define hydro_x25519_eswap_limb(X) LOAD32_LE((const uint8_t *) &(X))
#    define hydro_x25519_LIMB(x)       (uint32_t)(x##ull), (uint32_t) ((x##ull) >> 32)
#else
#    error "Need to know hydro_x25519_WBITS"
#endif

#define hydro_x25519_NLIMBS (256 / hydro_x25519_WBITS)
typedef hydro_x25519_limb_t hydro_x25519_fe[hydro_x25519_NLIMBS];

typedef hydro_x25519_limb_t hydro_x25519_scalar_t[hydro_x25519_NLIMBS];

static const hydro_x25519_limb_t hydro_x25519_MONTGOMERY_FACTOR =
    (hydro_x25519_limb_t) 0xd2b51da312547e1bull;

static const hydro_x25519_scalar_t hydro_x25519_sc_p = { hydro_x25519_LIMB(0x5812631a5cf5d3ed),
                                                         hydro_x25519_LIMB(0x14def9dea2f79cd6),
                                                         hydro_x25519_LIMB(0x0000000000000000),
                                                         hydro_x25519_LIMB(0x1000000000000000) };

static const hydro_x25519_scalar_t hydro_x25519_sc_r2 = { hydro_x25519_LIMB(0xa40611e3449c0f01),
                                                          hydro_x25519_LIMB(0xd00e1ba768859347),
                                                          hydro_x25519_LIMB(0xceec73d217f5be65),
                                                          hydro_x25519_LIMB(0x0399411b7c309a3d) };

static const uint8_t hydro_x25519_BASE_POINT[hydro_x25519_BYTES] = { 9 };

static const hydro_x25519_limb_t hydro_x25519_a24[1] = { 121665 };

static inline hydro_x25519_limb_t
hydro_x25519_umaal(hydro_x25519_limb_t *carry, hydro_x25519_limb_t acc, hydro_x25519_limb_t mand,
                   hydro_x25519_limb_t mier)
{
    hydro_x25519_dlimb_t tmp = (hydro_x25519_dlimb_t) mand * mier + acc + *carry;

    *carry = tmp >> hydro_x25519_WBITS;
    return (hydro_x25519_limb_t) tmp;
}

static inline hydro_x25519_limb_t
hydro_x25519_adc(hydro_x25519_limb_t *carry, hydro_x25519_limb_t acc, hydro_x25519_limb_t mand)
{
    hydro_x25519_dlimb_t total = (hydro_x25519_dlimb_t) *carry + acc + mand;

    *carry = total >> hydro_x25519_WBITS;
    return (hydro_x25519_limb_t) total;
}

static inline hydro_x25519_limb_t
hydro_x25519_adc0(hydro_x25519_limb_t *carry, hydro_x25519_limb_t acc)
{
    hydro_x25519_dlimb_t total = (hydro_x25519_dlimb_t) *carry + acc;

    *carry = total >> hydro_x25519_WBITS;
    return (hydro_x25519_limb_t) total;
}

static void
hydro_x25519_propagate(hydro_x25519_fe x, hydro_x25519_limb_t over)
{
    hydro_x25519_limb_t carry;
    int                 i;

    over = x[hydro_x25519_NLIMBS - 1] >> (hydro_x25519_WBITS - 1) | over << 1;
    x[hydro_x25519_NLIMBS - 1] &= ~((hydro_x25519_limb_t) 1 << (hydro_x25519_WBITS - 1));
    carry = over * 19;
    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        x[i] = hydro_x25519_adc0(&carry, x[i]);
    }
}

static void
hydro_x25519_add(hydro_x25519_fe out, const hydro_x25519_fe a, const hydro_x25519_fe b)
{
    hydro_x25519_limb_t carry = 0;
    int                 i;

    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        out[i] = hydro_x25519_adc(&carry, a[i], b[i]);
    }
    hydro_x25519_propagate(out, carry);
}

static void
hydro_x25519_sub(hydro_x25519_fe out, const hydro_x25519_fe a, const hydro_x25519_fe b)
{
    hydro_x25519_sdlimb_t carry = -76;
    int                   i;

    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        out[i] = (hydro_x25519_limb_t) (carry = carry + a[i] - b[i]);
        carry >>= hydro_x25519_WBITS;
    }
    hydro_x25519_propagate(out, (hydro_x25519_limb_t) (2 + carry));
}

static void
hydro_x25519_swapin(hydro_x25519_limb_t *x, const uint8_t *in)
{
    int i;

    memcpy(x, in, sizeof(hydro_x25519_fe));
    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        x[i] = hydro_x25519_eswap_limb(x[i]);
    }
}

static void
hydro_x25519_swapout(uint8_t *out, hydro_x25519_limb_t *x)
{
    int i;

    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        x[i] = hydro_x25519_eswap_limb(x[i]);
    }
    memcpy(out, x, sizeof(hydro_x25519_fe));
}

static void
hydro_x25519_mul(hydro_x25519_fe out, const hydro_x25519_fe a, const hydro_x25519_limb_t b[],
                 const int nb)
{
    hydro_x25519_limb_t accum[2 * hydro_x25519_NLIMBS] = { 0 };
    hydro_x25519_limb_t carry2;
    int                 i, j;

    for (i = 0; i < nb; i++) {
        hydro_x25519_limb_t mand = b[i];
        carry2                   = 0;

        for (j = 0; j < hydro_x25519_NLIMBS; j++) {
            accum[i + j] = hydro_x25519_umaal(&carry2, accum[i + j], mand, a[j]);
        }
        accum[i + j] = carry2;
    }
    carry2 = 0;
    for (j = 0; j < hydro_x25519_NLIMBS; j++) {
        const hydro_x25519_limb_t mand = 38;

        out[j] = hydro_x25519_umaal(&carry2, accum[j], mand, accum[j + hydro_x25519_NLIMBS]);
    }
    hydro_x25519_propagate(out, carry2);
}

static void
hydro_x25519_sqr(hydro_x25519_fe out, const hydro_x25519_fe a)
{
    hydro_x25519_mul(out, a, a, hydro_x25519_NLIMBS);
}

static void
hydro_x25519_mul1(hydro_x25519_fe out, const hydro_x25519_fe a)
{
    hydro_x25519_mul(out, a, out, hydro_x25519_NLIMBS);
}

static void
hydro_x25519_sqr1(hydro_x25519_fe a)
{
    hydro_x25519_mul1(a, a);
}

static void
hydro_x25519_condswap(hydro_x25519_limb_t a[2 * hydro_x25519_NLIMBS],
                      hydro_x25519_limb_t b[2 * hydro_x25519_NLIMBS], hydro_x25519_limb_t doswap)
{
    int i;

    for (i = 0; i < 2 * hydro_x25519_NLIMBS; i++) {
        hydro_x25519_limb_t xorv = (a[i] ^ b[i]) & doswap;
        a[i] ^= xorv;
        b[i] ^= xorv;
    }
}

static int
hydro_x25519_canon(hydro_x25519_fe x)
{
    hydro_x25519_sdlimb_t carry;
    hydro_x25519_limb_t   carry0 = 19;
    hydro_x25519_limb_t   res;
    int                   i;

    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        x[i] = hydro_x25519_adc0(&carry0, x[i]);
    }
    hydro_x25519_propagate(x, carry0);
    carry = -19;
    res   = 0;
    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        res |= x[i] = (hydro_x25519_limb_t) (carry += x[i]);
        carry >>= hydro_x25519_WBITS;
    }
    return ((hydro_x25519_dlimb_t) res - 1) >> hydro_x25519_WBITS;
}

static void
hydro_x25519_ladder_part1(hydro_x25519_fe xs[5])
{
    hydro_x25519_limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

    hydro_x25519_add(t1, x2, z2); // t1 = A
    hydro_x25519_sub(z2, x2, z2); // z2 = B
    hydro_x25519_add(x2, x3, z3); // x2 = C
    hydro_x25519_sub(z3, x3, z3); // z3 = D
    hydro_x25519_mul1(z3, t1); // z3 = DA
    hydro_x25519_mul1(x2, z2); // x3 = BC
    hydro_x25519_add(x3, z3, x2); // x3 = DA+CB
    hydro_x25519_sub(z3, z3, x2); // z3 = DA-CB
    hydro_x25519_sqr1(t1); // t1 = AA
    hydro_x25519_sqr1(z2); // z2 = BB
    hydro_x25519_sub(x2, t1, z2); // x2 = E = AA-BB
    hydro_x25519_mul(z2, x2, hydro_x25519_a24, // z2 = E*a24
                     sizeof(hydro_x25519_a24) / sizeof(hydro_x25519_a24[0]));
    hydro_x25519_add(z2, z2, t1); // z2 = E*a24 + AA
}

static void
hydro_x25519_ladder_part2(hydro_x25519_fe xs[5], const hydro_x25519_fe x1)
{
    hydro_x25519_limb_t *x2 = xs[0], *z2 = xs[1], *x3 = xs[2], *z3 = xs[3], *t1 = xs[4];

    hydro_x25519_sqr1(z3); // z3 = (DA-CB)^2
    hydro_x25519_mul1(z3, x1); // z3 = x1 * (DA-CB)^2
    hydro_x25519_sqr1(x3); // x3 = (DA+CB)^2
    hydro_x25519_mul1(z2, x2); // z2 = AA*(E*a24+AA)
    hydro_x25519_sub(x2, t1, x2); // x2 = BB again
    hydro_x25519_mul1(x2, t1); // x2 = AA*BB
}

static void
hydro_x25519_core(hydro_x25519_fe xs[5], const uint8_t scalar[hydro_x25519_BYTES],
                  const uint8_t *x1, bool clamp)
{
    hydro_x25519_limb_t  swap;
    hydro_x25519_limb_t *x2 = xs[0], *x3 = xs[2], *z3 = xs[3];
    hydro_x25519_fe      x1i;
    int                  i;

    hydro_x25519_swapin(x1i, x1);
    x1   = (const uint8_t *) x1i;
    swap = 0;
    mem_zero(xs, 4 * sizeof(hydro_x25519_fe));
    x2[0] = z3[0] = 1;
    memcpy(x3, x1, sizeof(hydro_x25519_fe));
    for (i = 255; i >= 0; i--) {
        uint8_t             bytei = scalar[i / 8];
        hydro_x25519_limb_t doswap;
        hydro_x25519_fe     x1_dup;

        if (clamp) {
            if (i / 8 == 0) {
                bytei &= ~7;
            } else if (i / 8 == hydro_x25519_BYTES - 1) {
                bytei &= 0x7F;
                bytei |= 0x40;
            }
        }
        doswap = 1U + ~(hydro_x25519_limb_t) ((bytei >> (i % 8)) & 1);
        hydro_x25519_condswap(x2, x3, swap ^ doswap);
        swap = doswap;
        hydro_x25519_ladder_part1(xs);
        memcpy(x1_dup, x1, sizeof x1_dup);
        hydro_x25519_ladder_part2(xs, x1_dup);
    }
    hydro_x25519_condswap(x2, x3, swap);
}

static int
hydro_x25519_scalarmult(uint8_t       out[hydro_x25519_BYTES],
                        const uint8_t scalar[hydro_x25519_SECRETKEYBYTES],
                        const uint8_t x1[hydro_x25519_PUBLICKEYBYTES], bool clamp)
{
    hydro_x25519_fe      xs[5];
    hydro_x25519_limb_t *x2, *z2, *z3;
    hydro_x25519_limb_t *prev;
    int                  i;
    int                  ret;

    hydro_x25519_core(xs, scalar, x1, clamp);

    /* Precomputed inversion chain */
    x2   = xs[0];
    z2   = xs[1];
    z3   = xs[3];
    prev = z2;

    /* Raise to the p-2 = 0x7f..ffeb */
    for (i = 253; i >= 0; i--) {
        hydro_x25519_sqr(z3, prev);
        prev = z3;
        if (i >= 8 || (0xeb >> i & 1)) {
            hydro_x25519_mul1(z3, z2);
        }
    }

    /* Here prev = z3 */
    /* x2 /= z2 */
    hydro_x25519_mul1(x2, z3);
    ret = hydro_x25519_canon(x2);
    hydro_x25519_swapout(out, x2);

    if (clamp == 0) {
        return 0;
    }
    return ret;
}

static inline int
hydro_x25519_scalarmult_base(uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
                             const uint8_t sk[hydro_x25519_SECRETKEYBYTES])
{
    return hydro_x25519_scalarmult(pk, sk, hydro_x25519_BASE_POINT, 1);
}

static inline void
hydro_x25519_scalarmult_base_uniform(uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
                                     const uint8_t sk[hydro_x25519_SECRETKEYBYTES])
{
    if (hydro_x25519_scalarmult(pk, sk, hydro_x25519_BASE_POINT, 0) != 0) {
        abort();
    }
}

static void
hydro_x25519_sc_montmul(hydro_x25519_scalar_t out, const hydro_x25519_scalar_t a,
                        const hydro_x25519_scalar_t b)
{
    hydro_x25519_limb_t hic = 0;
    int                 i, j;

    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        hydro_x25519_limb_t carry = 0, carry2 = 0, mand = a[i],
                            mand2 = hydro_x25519_MONTGOMERY_FACTOR;

        for (j = 0; j < hydro_x25519_NLIMBS; j++) {
            hydro_x25519_limb_t acc = out[j];

            acc = hydro_x25519_umaal(&carry, acc, mand, b[j]);
            if (j == 0) {
                mand2 *= acc;
            }
            acc = hydro_x25519_umaal(&carry2, acc, mand2, hydro_x25519_sc_p[j]);
            if (j > 0) {
                out[j - 1] = acc;
            }
        }

        /* Add two carry registers and high carry */
        out[hydro_x25519_NLIMBS - 1] = hydro_x25519_adc(&hic, carry, carry2);
    }

    /* Reduce */
    hydro_x25519_sdlimb_t scarry = 0;
    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        out[i] = (hydro_x25519_limb_t) (scarry = scarry + out[i] - hydro_x25519_sc_p[i]);
        scarry >>= hydro_x25519_WBITS;
    }
    hydro_x25519_limb_t need_add = (hydro_x25519_limb_t) - (scarry + hic);

    hydro_x25519_limb_t carry = 0;
    for (i = 0; i < hydro_x25519_NLIMBS; i++) {
        out[i] = hydro_x25519_umaal(&carry, out[i], need_add, hydro_x25519_sc_p[i]);
    }
}

// ----------------------------------------------------------------------------------------------------------

#define hydro_kx_AEAD_KEYBYTES hydro_hash_KEYBYTES
#define hydro_kx_AEAD_MACBYTES 16

#define hydro_kx_CONTEXT "hydro_kx"

static void
hydro_kx_aead_init(uint8_t aead_state[gimli_BLOCKBYTES], uint8_t k[hydro_kx_AEAD_KEYBYTES],
                   hydro_kx_state *state)
{
    static const uint8_t prefix[] = { 6, 'k', 'x', 'x', '2', '5', '6', 0 };

    hydro_hash_final(&state->h_st, k, hydro_kx_AEAD_KEYBYTES);

    mem_zero(aead_state + sizeof prefix, gimli_BLOCKBYTES - sizeof prefix);
    memcpy(aead_state, prefix, sizeof prefix);
    gimli_core_u8(aead_state, gimli_TAG_HEADER);

    COMPILER_ASSERT(hydro_kx_AEAD_KEYBYTES == 2 * gimli_RATE);
    mem_xor(aead_state, k, gimli_RATE);
    gimli_core_u8(aead_state, gimli_TAG_KEY);
    mem_xor(aead_state, k + gimli_RATE, gimli_RATE);
    gimli_core_u8(aead_state, gimli_TAG_KEY);
}

static void
hydro_kx_aead_final(uint8_t *aead_state, const uint8_t key[hydro_kx_AEAD_KEYBYTES])
{
    COMPILER_ASSERT(hydro_kx_AEAD_KEYBYTES == gimli_CAPACITY);
    mem_xor(aead_state + gimli_RATE, key, hydro_kx_AEAD_KEYBYTES);
    gimli_core_u8(aead_state, gimli_TAG_FINAL);
    mem_xor(aead_state + gimli_RATE, key, hydro_kx_AEAD_KEYBYTES);
    gimli_core_u8(aead_state, gimli_TAG_FINAL);
}

static void
hydro_kx_aead_xor_enc(uint8_t aead_state[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in,
                      size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], aead_state, gimli_RATE);
        memcpy(aead_state, &out[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(aead_state, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], aead_state, leftover);
        mem_cpy(aead_state, &out[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(aead_state, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(aead_state, gimli_TAG_PAYLOAD);
}

static void
hydro_kx_aead_xor_dec(uint8_t aead_state[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in,
                      size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], aead_state, gimli_RATE);
        memcpy(aead_state, &in[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(aead_state, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], aead_state, leftover);
        mem_cpy(aead_state, &in[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(aead_state, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(aead_state, gimli_TAG_PAYLOAD);
}

static void
hydro_kx_aead_encrypt(hydro_kx_state *state, uint8_t *c, const uint8_t *m, size_t mlen)
{
    _hydro_attr_aligned_(16) uint8_t aead_state[gimli_BLOCKBYTES];
    uint8_t                          k[hydro_kx_AEAD_KEYBYTES];
    uint8_t                         *mac = &c[0];
    uint8_t                         *ct  = &c[hydro_kx_AEAD_MACBYTES];

    hydro_kx_aead_init(aead_state, k, state);
    hydro_kx_aead_xor_enc(aead_state, ct, m, mlen);
    hydro_kx_aead_final(aead_state, k);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_CAPACITY);
    memcpy(mac, aead_state + gimli_RATE, hydro_kx_AEAD_MACBYTES);
    hydro_hash_update(&state->h_st, c, mlen + hydro_kx_AEAD_MACBYTES);
}

static int hydro_kx_aead_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c,
                                 size_t clen) _hydro_attr_warn_unused_result_;

static int
hydro_kx_aead_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c, size_t clen)
{
    _hydro_attr_aligned_(16) uint32_t int_state[gimli_BLOCKBYTES / 4];
    uint32_t                          pub_mac[hydro_kx_AEAD_MACBYTES / 4];
    uint8_t                           k[hydro_kx_AEAD_KEYBYTES];
    uint8_t                          *aead_state = (uint8_t *) (void *) int_state;
    const uint8_t                    *mac;
    const uint8_t                    *ct;
    size_t                            mlen;
    uint32_t                          cv;

    if (clen < hydro_kx_AEAD_MACBYTES) {
        return -1;
    }
    mac  = &c[0];
    ct   = &c[hydro_kx_AEAD_MACBYTES];
    mlen = clen - hydro_kx_AEAD_MACBYTES;
    memcpy(pub_mac, mac, sizeof pub_mac);
    hydro_kx_aead_init(aead_state, k, state);
    hydro_hash_update(&state->h_st, c, clen);
    hydro_kx_aead_xor_dec(aead_state, m, ct, mlen);
    hydro_kx_aead_final(aead_state, k);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_CAPACITY);
    COMPILER_ASSERT(gimli_RATE % 4 == 0);
    cv = hydro_mem_ct_cmp_u32(int_state + gimli_RATE / 4, pub_mac, hydro_kx_AEAD_MACBYTES / 4);
    hydro_mem_ct_zero_u32(int_state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}

/* -- */

void
hydro_kx_keygen(hydro_kx_keypair *static_kp)
{
    hydro_random_buf(static_kp->sk, hydro_kx_SECRETKEYBYTES);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

void
hydro_kx_keygen_deterministic(hydro_kx_keypair *static_kp, const uint8_t seed[hydro_kx_SEEDBYTES])
{
    COMPILER_ASSERT(hydro_kx_SEEDBYTES >= hydro_random_SEEDBYTES);
    hydro_random_buf_deterministic(static_kp->sk, hydro_kx_SECRETKEYBYTES, seed);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

static void
hydro_kx_init_state(hydro_kx_state *state, const char *name)
{
    mem_zero(state, sizeof *state);
    hydro_hash_init(&state->h_st, hydro_kx_CONTEXT, NULL);
    hydro_hash_update(&state->h_st, name, strlen(name));
    hydro_hash_final(&state->h_st, NULL, 0);
}

static void
hydro_kx_final(hydro_kx_state *state, uint8_t session_k1[hydro_kx_SESSIONKEYBYTES],
               uint8_t session_k2[hydro_kx_SESSIONKEYBYTES])
{
    uint8_t kdf_key[hydro_kdf_KEYBYTES];

    hydro_hash_final(&state->h_st, kdf_key, sizeof kdf_key);
    hydro_kdf_derive_from_key(session_k1, hydro_kx_SESSIONKEYBYTES, 0, hydro_kx_CONTEXT, kdf_key);
    hydro_kdf_derive_from_key(session_k2, hydro_kx_SESSIONKEYBYTES, 1, hydro_kx_CONTEXT, kdf_key);
}

static int
hydro_kx_dh(hydro_kx_state *state, const uint8_t sk[hydro_x25519_SECRETKEYBYTES],
            const uint8_t pk[hydro_x25519_PUBLICKEYBYTES])
{
    uint8_t dh_result[hydro_x25519_BYTES];

    if (hydro_x25519_scalarmult(dh_result, sk, pk, 1) != 0) {
        return -1;
    }
    hydro_hash_update(&state->h_st, dh_result, hydro_x25519_BYTES);

    return 0;
}

static void
hydro_kx_eph_keygen(hydro_kx_state *state, hydro_kx_keypair *kp)
{
    hydro_kx_keygen(kp);
    hydro_hash_update(&state->h_st, kp->pk, sizeof kp->pk);
}

/* NOISE_N */

int
hydro_kx_n_1(hydro_kx_session_keypair *kp, uint8_t packet1[hydro_kx_N_PACKET1BYTES],
             const uint8_t psk[hydro_kx_PSKBYTES],
             const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES])
{
    hydro_kx_state state;
    uint8_t       *packet1_eph_pk = &packet1[0];
    uint8_t       *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(&state, "Noise_Npsk0_hydro1");
    hydro_hash_update(&state.h_st, peer_static_pk, hydro_x25519_PUBLICKEYBYTES);

    hydro_hash_update(&state.h_st, psk, hydro_kx_PSKBYTES);
    hydro_kx_eph_keygen(&state, &state.eph_kp);
    if (hydro_kx_dh(&state, state.eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(&state, packet1_mac, NULL, 0);
    memcpy(packet1_eph_pk, state.eph_kp.pk, sizeof state.eph_kp.pk);

    hydro_kx_final(&state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_n_2(hydro_kx_session_keypair *kp, const uint8_t packet1[hydro_kx_N_PACKET1BYTES],
             const uint8_t psk[hydro_kx_PSKBYTES], const hydro_kx_keypair *static_kp)
{
    hydro_kx_state state;
    const uint8_t *peer_eph_pk = &packet1[0];
    const uint8_t *packet1_mac = &packet1[hydro_kx_PUBLICKEYBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(&state, "Noise_Npsk0_hydro1");
    hydro_hash_update(&state.h_st, static_kp->pk, hydro_kx_PUBLICKEYBYTES);

    hydro_hash_update(&state.h_st, psk, hydro_kx_PSKBYTES);
    hydro_hash_update(&state.h_st, peer_eph_pk, hydro_x25519_PUBLICKEYBYTES);
    if (hydro_kx_dh(&state, static_kp->sk, peer_eph_pk) != 0 ||
        hydro_kx_aead_decrypt(&state, NULL, packet1_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }
    hydro_kx_final(&state, kp->tx, kp->rx);

    return 0;
}

/* NOISE_KK */

int
hydro_kx_kk_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_KK_PACKET1BYTES],
              const uint8_t           peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t *packet1_eph_pk = &packet1[0];
    uint8_t *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];

    hydro_kx_init_state(state, "Noise_KK_hydro1");
    hydro_hash_update(&state->h_st, static_kp->pk, hydro_kx_PUBLICKEYBYTES);
    hydro_hash_update(&state->h_st, peer_static_pk, hydro_kx_PUBLICKEYBYTES);

    hydro_kx_eph_keygen(state, &state->eph_kp);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_static_pk) != 0 ||
        hydro_kx_dh(state, static_kp->sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(state, packet1_mac, NULL, 0);
    memcpy(packet1_eph_pk, state->eph_kp.pk, sizeof state->eph_kp.pk);

    return 0;
}

int
hydro_kx_kk_2(hydro_kx_session_keypair *kp, uint8_t packet2[hydro_kx_KK_PACKET2BYTES],
              const uint8_t           packet1[hydro_kx_KK_PACKET1BYTES],
              const uint8_t           peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const hydro_kx_keypair *static_kp)
{
    hydro_kx_state state;
    const uint8_t *peer_eph_pk    = &packet1[0];
    const uint8_t *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];
    uint8_t       *packet2_eph_pk = &packet2[0];
    uint8_t       *packet2_mac    = &packet2[hydro_kx_PUBLICKEYBYTES];

    hydro_kx_init_state(&state, "Noise_KK_hydro1");
    hydro_hash_update(&state.h_st, peer_static_pk, hydro_kx_PUBLICKEYBYTES);
    hydro_hash_update(&state.h_st, static_kp->pk, hydro_kx_PUBLICKEYBYTES);

    hydro_hash_update(&state.h_st, peer_eph_pk, hydro_kx_PUBLICKEYBYTES);
    if (hydro_kx_dh(&state, static_kp->sk, peer_eph_pk) != 0 ||
        hydro_kx_dh(&state, static_kp->sk, peer_static_pk) != 0 ||
        hydro_kx_aead_decrypt(&state, NULL, packet1_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }

    hydro_kx_eph_keygen(&state, &state.eph_kp);
    if (hydro_kx_dh(&state, state.eph_kp.sk, peer_eph_pk) != 0 ||
        hydro_kx_dh(&state, state.eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(&state, packet2_mac, NULL, 0);
    hydro_kx_final(&state, kp->tx, kp->rx);
    memcpy(packet2_eph_pk, state.eph_kp.pk, sizeof state.eph_kp.pk);

    return 0;
}

int
hydro_kx_kk_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              const uint8_t packet2[hydro_kx_KK_PACKET2BYTES], const hydro_kx_keypair *static_kp)
{
    const uint8_t *peer_eph_pk = packet2;
    const uint8_t *packet2_mac = &packet2[hydro_kx_PUBLICKEYBYTES];

    hydro_hash_update(&state->h_st, peer_eph_pk, hydro_kx_PUBLICKEYBYTES);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_eph_pk) != 0 ||
        hydro_kx_dh(state, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }

    if (hydro_kx_aead_decrypt(state, NULL, packet2_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->rx, kp->tx);

    return 0;
}

/* NOISE_XX */

int
hydro_kx_xx_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_XX_PACKET1BYTES],
              const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t *packet1_eph_pk = &packet1[0];
    uint8_t *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(state, "Noise_XXpsk0+psk3_hydro1");

    hydro_kx_eph_keygen(state, &state->eph_kp);
    hydro_hash_update(&state->h_st, psk, hydro_kx_PSKBYTES);
    memcpy(packet1_eph_pk, state->eph_kp.pk, sizeof state->eph_kp.pk);
    hydro_kx_aead_encrypt(state, packet1_mac, NULL, 0);

    return 0;
}

int
hydro_kx_xx_2(hydro_kx_state *state, uint8_t packet2[hydro_kx_XX_PACKET2BYTES],
              const uint8_t packet1[hydro_kx_XX_PACKET1BYTES], const uint8_t psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    const uint8_t *peer_eph_pk           = &packet1[0];
    const uint8_t *packet1_mac           = &packet1[hydro_kx_PUBLICKEYBYTES];
    uint8_t       *packet2_eph_pk        = &packet2[0];
    uint8_t       *packet2_enc_static_pk = &packet2[hydro_kx_PUBLICKEYBYTES];
    uint8_t       *packet2_mac =
        &packet2[hydro_kx_PUBLICKEYBYTES + hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(state, "Noise_XXpsk0+psk3_hydro1");

    hydro_hash_update(&state->h_st, peer_eph_pk, hydro_kx_PUBLICKEYBYTES);
    hydro_hash_update(&state->h_st, psk, hydro_kx_PSKBYTES);
    if (hydro_kx_aead_decrypt(state, NULL, packet1_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }

    hydro_kx_eph_keygen(state, &state->eph_kp);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(state, packet2_enc_static_pk, static_kp->pk, sizeof static_kp->pk);
    if (hydro_kx_dh(state, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(state, packet2_mac, NULL, 0);

    memcpy(packet2_eph_pk, state->eph_kp.pk, sizeof state->eph_kp.pk);

    return 0;
}

int
hydro_kx_xx_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t       packet3[hydro_kx_XX_PACKET3BYTES],
              uint8_t       peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t packet2[hydro_kx_XX_PACKET2BYTES], const uint8_t psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_eph_pk        = &packet2[0];
    const uint8_t *peer_enc_static_pk = &packet2[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *packet2_mac =
        &packet2[hydro_kx_PUBLICKEYBYTES + hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES];
    uint8_t *packet3_enc_static_pk = &packet3[0];
    uint8_t *packet3_mac           = &packet3[hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    hydro_hash_update(&state->h_st, peer_eph_pk, hydro_kx_PUBLICKEYBYTES);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_eph_pk) != 0 ||
        hydro_kx_aead_decrypt(state, peer_static_pk, peer_enc_static_pk,
                              hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES) != 0 ||
        hydro_kx_dh(state, state->eph_kp.sk, peer_static_pk) != 0 ||
        hydro_kx_aead_decrypt(state, NULL, packet2_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }

    hydro_kx_aead_encrypt(state, packet3_enc_static_pk, static_kp->pk, sizeof static_kp->pk);
    if (hydro_kx_dh(state, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_hash_update(&state->h_st, psk, hydro_kx_PSKBYTES);
    hydro_kx_aead_encrypt(state, packet3_mac, NULL, 0);
    hydro_kx_final(state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_xx_4(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t       peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t packet3[hydro_kx_XX_PACKET3BYTES], const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_enc_static_pk = &packet3[0];
    const uint8_t *packet3_mac        = &packet3[hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_kx_aead_decrypt(state, peer_static_pk, peer_enc_static_pk,
                              hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_MACBYTES) != 0 ||
        hydro_kx_dh(state, state->eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_hash_update(&state->h_st, psk, hydro_kx_PSKBYTES);
    if (hydro_kx_aead_decrypt(state, NULL, packet3_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->tx, kp->rx);

    return 0;
}

/* NOISE_NK */

int
hydro_kx_nk_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_NK_PACKET1BYTES],
              const uint8_t psk[hydro_kx_PSKBYTES],
              const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES])
{
    uint8_t *packet1_eph_pk = &packet1[0];
    uint8_t *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(state, "Noise_NKpsk0_hydro1");
    hydro_hash_update(&state->h_st, peer_static_pk, hydro_x25519_PUBLICKEYBYTES);

    hydro_hash_update(&state->h_st, psk, hydro_kx_PSKBYTES);
    hydro_kx_eph_keygen(state, &state->eph_kp);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(state, packet1_mac, NULL, 0);
    memcpy(packet1_eph_pk, state->eph_kp.pk, sizeof state->eph_kp.pk);

    return 0;
}

int
hydro_kx_nk_2(hydro_kx_session_keypair *kp, uint8_t packet2[hydro_kx_NK_PACKET2BYTES],
              const uint8_t packet1[hydro_kx_NK_PACKET1BYTES], const uint8_t psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    hydro_kx_state state;
    const uint8_t *peer_eph_pk    = &packet1[0];
    const uint8_t *packet1_mac    = &packet1[hydro_kx_PUBLICKEYBYTES];
    uint8_t       *packet2_eph_pk = &packet2[0];
    uint8_t       *packet2_mac    = &packet2[hydro_kx_PUBLICKEYBYTES];

    if (psk == NULL) {
        psk = zero;
    }
    hydro_kx_init_state(&state, "Noise_NKpsk0_hydro1");
    hydro_hash_update(&state.h_st, static_kp->pk, hydro_kx_PUBLICKEYBYTES);

    hydro_hash_update(&state.h_st, psk, hydro_kx_PSKBYTES);
    hydro_hash_update(&state.h_st, peer_eph_pk, hydro_x25519_PUBLICKEYBYTES);
    if (hydro_kx_dh(&state, static_kp->sk, peer_eph_pk) != 0 ||
        hydro_kx_aead_decrypt(&state, NULL, packet1_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }

    hydro_kx_eph_keygen(&state, &state.eph_kp);
    if (hydro_kx_dh(&state, state.eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_aead_encrypt(&state, packet2_mac, NULL, 0);
    hydro_kx_final(&state, kp->tx, kp->rx);
    memcpy(packet2_eph_pk, state.eph_kp.pk, sizeof state.eph_kp.pk);

    return 0;
}

int
hydro_kx_nk_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              const uint8_t packet2[hydro_kx_NK_PACKET2BYTES])
{
    const uint8_t *peer_eph_pk = &packet2[0];
    const uint8_t *packet2_mac = &packet2[hydro_kx_PUBLICKEYBYTES];

    hydro_hash_update(&state->h_st, peer_eph_pk, hydro_x25519_PUBLICKEYBYTES);
    if (hydro_kx_dh(state, state->eph_kp.sk, peer_eph_pk) != 0 ||
        hydro_kx_aead_decrypt(state, NULL, packet2_mac, hydro_kx_AEAD_MACBYTES) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->rx, kp->tx);

    return 0;
}

// ----------------------------------------------------------------------------------------------------------

#define hydro_sign_CHALLENGEBYTES 32
#define hydro_sign_NONCEBYTES     32
#define hydro_sign_PREHASHBYTES   64

static void
hydro_sign_p2(uint8_t sig[hydro_x25519_BYTES], const uint8_t challenge[hydro_sign_CHALLENGEBYTES],
              const uint8_t eph_sk[hydro_x25519_BYTES], const uint8_t sk[hydro_x25519_BYTES])
{
    hydro_x25519_scalar_t scalar1, scalar2, scalar3;

    COMPILER_ASSERT(hydro_sign_CHALLENGEBYTES == hydro_x25519_BYTES);
    hydro_x25519_swapin(scalar1, eph_sk);
    hydro_x25519_swapin(scalar2, sk);
    hydro_x25519_swapin(scalar3, challenge);
    hydro_x25519_sc_montmul(scalar1, scalar2, scalar3);
    mem_zero(scalar2, sizeof scalar2);
    hydro_x25519_sc_montmul(scalar2, scalar1, hydro_x25519_sc_r2);
    hydro_x25519_swapout(sig, scalar2);
}

static void
hydro_sign_challenge(uint8_t       challenge[hydro_sign_CHALLENGEBYTES],
                     const uint8_t nonce[hydro_sign_NONCEBYTES],
                     const uint8_t pk[hydro_sign_PUBLICKEYBYTES],
                     const uint8_t prehash[hydro_sign_PREHASHBYTES])
{
    hydro_hash_state st;

    hydro_hash_init(&st, (const char *) zero, NULL);
    hydro_hash_update(&st, nonce, hydro_sign_NONCEBYTES);
    hydro_hash_update(&st, pk, hydro_sign_PUBLICKEYBYTES);
    hydro_hash_update(&st, prehash, hydro_sign_PREHASHBYTES);
    hydro_hash_final(&st, challenge, hydro_sign_CHALLENGEBYTES);
}

static int
hydro_sign_prehash(uint8_t csig[hydro_sign_BYTES], const uint8_t prehash[hydro_sign_PREHASHBYTES],
                   const uint8_t sk[hydro_sign_SECRETKEYBYTES])
{
    hydro_hash_state st;
    uint8_t          challenge[hydro_sign_CHALLENGEBYTES];
    const uint8_t   *pk     = &sk[hydro_x25519_SECRETKEYBYTES];
    uint8_t         *nonce  = &csig[0];
    uint8_t         *sig    = &csig[hydro_sign_NONCEBYTES];
    uint8_t         *eph_sk = sig;

    hydro_random_buf(eph_sk, hydro_x25519_SECRETKEYBYTES);
    COMPILER_ASSERT(hydro_x25519_SECRETKEYBYTES == hydro_hash_KEYBYTES);
    hydro_hash_init(&st, (const char *) zero, sk);
    hydro_hash_update(&st, eph_sk, hydro_x25519_SECRETKEYBYTES);
    hydro_hash_update(&st, prehash, hydro_sign_PREHASHBYTES);
    hydro_hash_final(&st, eph_sk, hydro_x25519_SECRETKEYBYTES);

    hydro_x25519_scalarmult_base_uniform(nonce, eph_sk);
    hydro_sign_challenge(challenge, nonce, pk, prehash);

    COMPILER_ASSERT(hydro_sign_BYTES == hydro_sign_NONCEBYTES + hydro_x25519_SECRETKEYBYTES);
    COMPILER_ASSERT(hydro_x25519_SECRETKEYBYTES <= hydro_sign_CHALLENGEBYTES);
    hydro_sign_p2(sig, challenge, eph_sk, sk);

    return 0;
}

static int
hydro_sign_verify_core(hydro_x25519_fe xs[5], const hydro_x25519_limb_t *other1,
                       const uint8_t other2[hydro_x25519_BYTES])
{
    hydro_x25519_limb_t      *z2 = xs[1], *x3 = xs[2], *z3 = xs[3];
    hydro_x25519_fe           xo2;
    const hydro_x25519_limb_t sixteen = 16;

    hydro_x25519_swapin(xo2, other2);
    memcpy(x3, other1, 2 * sizeof(hydro_x25519_fe));
    hydro_x25519_ladder_part1(xs);

    /* Here z2 = t2^2 */
    hydro_x25519_mul1(z2, other1);
    hydro_x25519_mul1(z2, other1 + hydro_x25519_NLIMBS);
    hydro_x25519_mul1(z2, xo2);

    hydro_x25519_mul(z2, z2, &sixteen, 1);

    hydro_x25519_mul1(z3, xo2);
    hydro_x25519_sub(z3, z3, x3);
    hydro_x25519_sqr1(z3);

    /* check equality */
    hydro_x25519_sub(z3, z3, z2);

    /* canon(z2): both sides are zero. canon(z3): the two sides are equal. */
    /* Reject sigs where both sides are zero. */
    return hydro_x25519_canon(z2) | ~hydro_x25519_canon(z3);
}

static int
hydro_sign_verify_p2(const uint8_t sig[hydro_x25519_BYTES],
                     const uint8_t challenge[hydro_sign_CHALLENGEBYTES],
                     const uint8_t nonce[hydro_sign_NONCEBYTES],
                     const uint8_t pk[hydro_x25519_BYTES])
{
    hydro_x25519_fe xs[7];

    hydro_x25519_core(xs, challenge, pk, 0);
    hydro_x25519_core(xs + 2, sig, hydro_x25519_BASE_POINT, 0);

    return hydro_sign_verify_core(xs + 2, xs[0], nonce);
}

static int
hydro_sign_verify_challenge(const uint8_t csig[hydro_sign_BYTES],
                            const uint8_t challenge[hydro_sign_CHALLENGEBYTES],
                            const uint8_t pk[hydro_sign_PUBLICKEYBYTES])
{
    const uint8_t *nonce = &csig[0];
    const uint8_t *sig   = &csig[hydro_sign_NONCEBYTES];

    return hydro_sign_verify_p2(sig, challenge, nonce, pk);
}

void
hydro_sign_keygen(hydro_sign_keypair *kp)
{
    uint8_t *pk_copy = &kp->sk[hydro_x25519_SECRETKEYBYTES];

    COMPILER_ASSERT(hydro_sign_SECRETKEYBYTES ==
                    hydro_x25519_SECRETKEYBYTES + hydro_x25519_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_sign_PUBLICKEYBYTES == hydro_x25519_PUBLICKEYBYTES);
    hydro_random_buf(kp->sk, hydro_x25519_SECRETKEYBYTES);
    hydro_x25519_scalarmult_base_uniform(kp->pk, kp->sk);
    memcpy(pk_copy, kp->pk, hydro_x25519_PUBLICKEYBYTES);
}

void
hydro_sign_keygen_deterministic(hydro_sign_keypair *kp, const uint8_t seed[hydro_sign_SEEDBYTES])
{
    uint8_t *pk_copy = &kp->sk[hydro_x25519_SECRETKEYBYTES];

    COMPILER_ASSERT(hydro_sign_SEEDBYTES >= hydro_random_SEEDBYTES);
    hydro_random_buf_deterministic(kp->sk, hydro_x25519_SECRETKEYBYTES, seed);
    hydro_x25519_scalarmult_base_uniform(kp->pk, kp->sk);
    memcpy(pk_copy, kp->pk, hydro_x25519_PUBLICKEYBYTES);
}

int
hydro_sign_init(hydro_sign_state *state, const char ctx[hydro_sign_CONTEXTBYTES])
{
    return hydro_hash_init(&state->hash_st, ctx, NULL);
}

int
hydro_sign_update(hydro_sign_state *state, const void *m_, size_t mlen)
{
    return hydro_hash_update(&state->hash_st, m_, mlen);
}

int
hydro_sign_final_create(hydro_sign_state *state, uint8_t csig[hydro_sign_BYTES],
                        const uint8_t sk[hydro_sign_SECRETKEYBYTES])
{
    uint8_t prehash[hydro_sign_PREHASHBYTES];

    hydro_hash_final(&state->hash_st, prehash, sizeof prehash);

    return hydro_sign_prehash(csig, prehash, sk);
}

int
hydro_sign_final_verify(hydro_sign_state *state, const uint8_t csig[hydro_sign_BYTES],
                        const uint8_t pk[hydro_sign_PUBLICKEYBYTES])
{
    uint8_t        challenge[hydro_sign_CHALLENGEBYTES];
    uint8_t        prehash[hydro_sign_PREHASHBYTES];
    const uint8_t *nonce = &csig[0];

    hydro_hash_final(&state->hash_st, prehash, sizeof prehash);
    hydro_sign_challenge(challenge, nonce, pk, prehash);

    return hydro_sign_verify_challenge(csig, challenge, pk);
}

int
hydro_sign_create(uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen,
                  const char    ctx[hydro_sign_CONTEXTBYTES],
                  const uint8_t sk[hydro_sign_SECRETKEYBYTES])
{
    hydro_sign_state st;

    if (hydro_sign_init(&st, ctx) != 0 || hydro_sign_update(&st, m_, mlen) != 0 ||
        hydro_sign_final_create(&st, csig, sk) != 0) {
        return -1;
    }
    return 0;
}

int
hydro_sign_verify(const uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen,
                  const char    ctx[hydro_sign_CONTEXTBYTES],
                  const uint8_t pk[hydro_sign_PUBLICKEYBYTES])
{
    hydro_sign_state st;

    if (hydro_sign_init(&st, ctx) != 0 || hydro_sign_update(&st, m_, mlen) != 0 ||
        hydro_sign_final_verify(&st, csig, pk) != 0) {
        return -1;
    }
    return 0;
}

// ----------------------------------------------------------------------------------------------------------

void warnings_fuck_off(void);       // -Wmissing-prototypes

void warnings_fuck_off(void)
{
    (void) load16_le;
    (void) store16_le;
    (void) load32_le;
    (void) store32_le;
    (void) load64_le;
    (void) store64_le;

    (void) load16_be;
    (void) store16_be;
    (void) load32_be;
    (void) store32_be;
    (void) load64_be;
    (void) store64_be;
}

// ----------------------------------------------------------------------------------------------------------
