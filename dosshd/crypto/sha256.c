/*
 * SHA-256 (FIPS 180-4) - public-domain implementation.
 * See sha256.h for provenance and licence (public domain).
 */
#include "sha256.h"

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)   (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)   (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)  (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)  (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data)
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
	int i, j;

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
		       ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0]; b = ctx->state[1];
	c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5];
	g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b;
	ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f;
	ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx)
{
	ctx->datalen   = 0;
	ctx->bitlen_lo = 0;
	ctx->bitlen_hi = 0;
	ctx->state[0] = 0x6a09e667UL;
	ctx->state[1] = 0xbb67ae85UL;
	ctx->state[2] = 0x3c6ef372UL;
	ctx->state[3] = 0xa54ff53aUL;
	ctx->state[4] = 0x510e527fUL;
	ctx->state[5] = 0x9b05688cUL;
	ctx->state[6] = 0x1f83d9abUL;
	ctx->state[7] = 0x5be0cd19UL;
}

/* add (bytes * 8) to the 64-bit message-length counter */
static void sha256_addlen(sha256_ctx *ctx, uint32_t bytes)
{
	uint32_t add = bytes << 3;            /* bytes < 64, so no overflow here */
	uint32_t old = ctx->bitlen_lo;
	ctx->bitlen_lo = old + add;
	if (ctx->bitlen_lo < old)
		ctx->bitlen_hi++;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			sha256_addlen(ctx, 64);
			ctx->datalen = 0;
		}
	}
}

void sha256_final(sha256_ctx *ctx, uint8_t hash[32])
{
	uint32_t i = ctx->datalen;

	/* fold in the bits still buffered, then append the 0x80 pad byte */
	sha256_addlen(ctx, ctx->datalen);

	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		for (i = 0; i < 56; ++i)
			ctx->data[i] = 0x00;
	}

	/* append the 64-bit big-endian message length in bits */
	ctx->data[56] = (uint8_t)(ctx->bitlen_hi >> 24);
	ctx->data[57] = (uint8_t)(ctx->bitlen_hi >> 16);
	ctx->data[58] = (uint8_t)(ctx->bitlen_hi >> 8);
	ctx->data[59] = (uint8_t)(ctx->bitlen_hi);
	ctx->data[60] = (uint8_t)(ctx->bitlen_lo >> 24);
	ctx->data[61] = (uint8_t)(ctx->bitlen_lo >> 16);
	ctx->data[62] = (uint8_t)(ctx->bitlen_lo >> 8);
	ctx->data[63] = (uint8_t)(ctx->bitlen_lo);
	sha256_transform(ctx, ctx->data);

	/* emit the digest, big-endian */
	for (i = 0; i < 4; ++i) {
		hash[i]      = (uint8_t)(ctx->state[0] >> (24 - i * 8));
		hash[i + 4]  = (uint8_t)(ctx->state[1] >> (24 - i * 8));
		hash[i + 8]  = (uint8_t)(ctx->state[2] >> (24 - i * 8));
		hash[i + 12] = (uint8_t)(ctx->state[3] >> (24 - i * 8));
		hash[i + 16] = (uint8_t)(ctx->state[4] >> (24 - i * 8));
		hash[i + 20] = (uint8_t)(ctx->state[5] >> (24 - i * 8));
		hash[i + 24] = (uint8_t)(ctx->state[6] >> (24 - i * 8));
		hash[i + 28] = (uint8_t)(ctx->state[7] >> (24 - i * 8));
	}
}

void sha256(uint8_t hash[32], const uint8_t *data, size_t len)
{
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, hash);
}
