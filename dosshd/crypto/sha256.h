/*
 * SHA-256 (FIPS 180-4) - public-domain implementation.
 *
 * Derived from Brad Conte's public-domain crypto-algorithms
 * (https://github.com/B-Con/crypto-algorithms), which its author released
 * into the public domain. Trimmed to just SHA-256 and adjusted to track the
 * message bit length as two 32-bit words so no 64-bit integer type is needed
 * (Watcom 16-bit real mode has no cheap "long long").
 *
 * Monocypher ships SHA-512 and BLAKE2b but not SHA-256; SSH's
 * curve25519-sha256 key exchange needs it, so it lives here.
 *
 * To the extent possible under law, this file is dedicated to the public
 * domain. It carries no warranty.
 */
#ifndef DOSSH_SHA256_H
#define DOSSH_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32   /* digest length in bytes */

typedef struct {
	uint8_t  data[64];
	uint32_t datalen;      /* bytes buffered in data[] (0..63) */
	uint32_t bitlen_lo;    /* total message bit length, low 32 bits */
	uint32_t bitlen_hi;    /* total message bit length, high 32 bits */
	uint32_t state[8];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[32]);

/* one-shot convenience */
void sha256(uint8_t hash[32], const uint8_t *data, size_t len);

#endif /* DOSSH_SHA256_H */
