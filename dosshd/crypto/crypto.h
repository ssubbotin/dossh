/*
 * DOSSH crypto foundation - thin wrappers over the vendored Monocypher
 * (dual-licensed BSD-2-Clause / CC0-1.0) plus a public-domain SHA-256.
 *
 * These are the primitives a future in-DOS SSH server needs:
 *   - x25519 scalar multiplication      (curve25519-sha256 key exchange)
 *   - ed25519 keygen / sign / verify     (ssh-ed25519 host key, RFC 8032)
 *   - chacha20-poly1305 AEAD             (chacha20-poly1305@openssh.com)
 *   - sha256                             (curve25519-sha256 exchange hash)
 *   - sha512                             (used inside ed25519)
 *
 * NOTE: the crypto module is built with `wcc -3` (386 real mode) because
 * Monocypher's field arithmetic is 64-bit; on an 8086 (-0) every 64-bit op is
 * a slow Watcom runtime call. SSH therefore requires a 386 or better. The rest
 * of DOSSH stays 8086-clean; only the crypto objects are 386, linked into the
 * same small-model image. See dosshd/build.sh.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_CRYPTO_H
#define DOSSH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * FAR calling convention on 16-bit DOS. The vendored Monocypher's compiled
 * 16-bit code does not fit a single 64K near-code segment, so the crypto
 * module is built as medium model (far code, near data) and lives in its own
 * code segment(s). DOSSHD itself stays small model (near code), so it must
 * reach the crypto through FAR calls; marking the public API __far makes any
 * caller emit one, whatever its own model. Data pointers stay near (both
 * DOSSHD and the crypto use near data), so buffers pass straight through.
 * On the native KAT host this macro is empty. */
#if defined(__WATCOMC__) && defined(__I86__)
#  define DOSSH_FAR __far
#else
#  define DOSSH_FAR
#endif

/* ---- X25519 (RFC 7748) --------------------------------------------- */

/* Raw scalar multiplication: shared = scalar * point (both 32 bytes).
 * The scalar is clamped internally, matching RFC 7748. */
void DOSSH_FAR dossh_x25519(uint8_t shared[32],
                            const uint8_t scalar[32],
                            const uint8_t point[32]);

/* Public key = scalar * basepoint(9). */
void DOSSH_FAR dossh_x25519_public_key(uint8_t pub[32], const uint8_t secret[32]);

/* ---- Ed25519 (RFC 8032, EdDSA with SHA-512) ------------------------ */

/* Derive a key pair from a 32-byte seed. secret_key is 64 bytes (the
 * standard "expanded" form: seed || public key). The seed is wiped. */
void DOSSH_FAR dossh_ed25519_key_pair(uint8_t secret_key[64],
                                      uint8_t public_key[32],
                                      uint8_t seed[32]);

void DOSSH_FAR dossh_ed25519_sign(uint8_t signature[64],
                                  const uint8_t secret_key[64],
                                  const uint8_t *msg, size_t msg_len);

/* Returns 0 if the signature is valid, nonzero otherwise. */
int DOSSH_FAR dossh_ed25519_verify(const uint8_t signature[64],
                                   const uint8_t public_key[32],
                                   const uint8_t *msg, size_t msg_len);

/* ---- ChaCha20-Poly1305 AEAD (RFC 8439, IETF 12-byte nonce) --------- */
/*
 * The IETF construction of RFC 8439: 96-bit nonce, 32-bit block counter,
 * Poly1305 key from block 0, encryption from block 1, and the MAC computed
 * over  ad || pad16 || cipher || pad16 || le64(ad_len) || le64(cipher_len).
 * This is the exact function the RFC 8439 section 2.8.2 KAT exercises.
 * Encrypts in place-capable buffers (cipher may alias plain). */

void DOSSH_FAR dossh_aead_lock(uint8_t *cipher, uint8_t mac[16],
                               const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *plain, size_t plain_len);

/* Returns 0 on success (MAC ok), nonzero on tamper/auth failure. */
int DOSSH_FAR dossh_aead_unlock(uint8_t *plain, const uint8_t mac[16],
                                const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *ad, size_t ad_len,
                                const uint8_t *cipher, size_t cipher_len);

/* ---- Raw ChaCha20 keystream (RFC 8439 IETF) ------------------------ */
/*
 * Writes n bytes of the ChaCha20 keystream (i.e. the cipher of an all-zero
 * plaintext) to out, for the given 256-bit key, 96-bit nonce and 32-bit
 * starting block counter. This is the unauthenticated stream primitive; the
 * SSH record layer uses the AEAD above, but the CSPRNG (rng.c) needs bare
 * keystream to drive a ChaCha20 DRBG. */
void DOSSH_FAR dossh_chacha20(uint8_t *out, const uint8_t key[32],
                              const uint8_t nonce[12], uint32_t counter,
                              size_t n);

/* ---- Raw ChaCha20 (original DJB variant: 64-bit nonce, 64-bit ctr) - */
/*
 * The original Bernstein ChaCha20 layout (8-byte nonce, 64-bit block counter),
 * as opposed to the IETF split above. This is the exact primitive the SSH
 * cipher chacha20-poly1305@openssh.com is built on: OpenSSH uses the 64-bit
 * packet sequence number (big-endian, 8 bytes) as the nonce. With in==NULL the
 * routine emits raw keystream into out; otherwise out = in XOR keystream (in
 * and out may alias). counter selects the starting 64-byte block.
 */
void DOSSH_FAR dossh_chacha20_djb(uint8_t *out, const uint8_t *in, size_t n,
                                  const uint8_t key[32], const uint8_t nonce[8],
                                  uint32_t counter);

/* ---- Poly1305 one-shot MAC (RFC 8439) ------------------------------ */
/* One-time authenticator: tag = Poly1305(msg, key). The 32-byte key is a
 * single-use value; disclosing a tag under a reused key reveals the key. SSH's
 * chacha20-poly1305 derives a fresh key per packet from the ChaCha20 stream. */
void DOSSH_FAR dossh_poly1305(uint8_t mac[16], const uint8_t *msg, size_t n,
                              const uint8_t key[32]);

/* ---- Hashes -------------------------------------------------------- */

void DOSSH_FAR dossh_sha256(uint8_t hash[32], const uint8_t *msg, size_t msg_len);
void DOSSH_FAR dossh_sha512(uint8_t hash[64], const uint8_t *msg, size_t msg_len);

#endif /* DOSSH_CRYPTO_H */
