/*
 * DOSSH crypto foundation - thin wrappers over Monocypher + SHA-256.
 * See crypto.h. MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include "crypto.h"
#include "sha256.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

void DOSSH_FAR dossh_x25519(uint8_t shared[32],
                  const uint8_t scalar[32],
                  const uint8_t point[32])
{
	crypto_x25519(shared, scalar, point);
}

void DOSSH_FAR dossh_x25519_public_key(uint8_t pub[32], const uint8_t secret[32])
{
	crypto_x25519_public_key(pub, secret);
}

void DOSSH_FAR dossh_ed25519_key_pair(uint8_t secret_key[64],
                            uint8_t public_key[32],
                            uint8_t seed[32])
{
	crypto_ed25519_key_pair(secret_key, public_key, seed);
}

void DOSSH_FAR dossh_ed25519_sign(uint8_t signature[64],
                        const uint8_t secret_key[64],
                        const uint8_t *msg, size_t msg_len)
{
	crypto_ed25519_sign(signature, secret_key, msg, msg_len);
}

int DOSSH_FAR dossh_ed25519_verify(const uint8_t signature[64],
                         const uint8_t public_key[32],
                         const uint8_t *msg, size_t msg_len)
{
	return crypto_ed25519_check(signature, public_key, msg, msg_len);
}

void DOSSH_FAR dossh_aead_lock(uint8_t *cipher, uint8_t mac[16],
                     const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *plain, size_t plain_len)
{
	crypto_aead_ctx ctx;
	crypto_aead_init_ietf(&ctx, key, nonce);
	crypto_aead_write(&ctx, cipher, mac, ad, ad_len, plain, plain_len);
	crypto_wipe(&ctx, sizeof(ctx));
}

int DOSSH_FAR dossh_aead_unlock(uint8_t *plain, const uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *cipher, size_t cipher_len)
{
	crypto_aead_ctx ctx;
	int r;
	crypto_aead_init_ietf(&ctx, key, nonce);
	r = crypto_aead_read(&ctx, plain, mac, ad, ad_len, cipher, cipher_len);
	crypto_wipe(&ctx, sizeof(ctx));
	return r;
}

void DOSSH_FAR dossh_chacha20(uint8_t *out, const uint8_t key[32],
                    const uint8_t nonce[12], uint32_t counter, size_t n)
{
	/* plain_text == NULL makes Monocypher emit raw keystream. */
	crypto_chacha20_ietf(out, (const uint8_t *)0, n, key, nonce, counter);
}

void DOSSH_FAR dossh_chacha20_djb(uint8_t *out, const uint8_t *in, size_t n,
                        const uint8_t key[32], const uint8_t nonce[8],
                        uint32_t counter)
{
	/* in == NULL makes Monocypher emit raw keystream. */
	crypto_chacha20_djb(out, in, n, key, nonce, (uint64_t)counter);
}

void DOSSH_FAR dossh_poly1305(uint8_t mac[16], const uint8_t *msg, size_t n,
                        const uint8_t key[32])
{
	crypto_poly1305(mac, msg, n, key);
}

void DOSSH_FAR dossh_sha256(uint8_t hash[32], const uint8_t *msg, size_t msg_len)
{
	sha256(hash, msg, msg_len);
}

void DOSSH_FAR dossh_sha512(uint8_t hash[64], const uint8_t *msg, size_t msg_len)
{
	crypto_sha512(hash, msg, msg_len);
}
