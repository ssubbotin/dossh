/*
 * Known-answer tests for the DOSSH crypto foundation (dosshd/crypto).
 *
 * Runs NATIVELY (compiled with cc on Linux, not in DOS): it links the very
 * same crypto .c files the DOS build uses and checks them against the official
 * published test vectors:
 *
 *   X25519              RFC 7748  section 5.2 (single scalarmult) + 6.1 (ECDH)
 *   Ed25519             RFC 8032  section 7.1 (sign/verify + tamper reject)
 *   ChaCha20-Poly1305   RFC 8439  section 2.8.2 (AEAD lock/unlock + tamper)
 *   SHA-256             NIST FIPS 180-4 examples ("abc", 448-bit, empty)
 *
 * Prints PASS/FAIL per vector and exits nonzero if any vector fails.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../dosshd/crypto/crypto.h"

static int g_fail = 0;
static int g_total = 0;

/* decode a hex string (no separators) into buf; returns the byte count */
static size_t hx(uint8_t *buf, const char *hex)
{
	size_t n = 0;
	while (hex[0] && hex[1]) {
		unsigned v;
		sscanf(hex, "%2x", &v);
		buf[n++] = (uint8_t)v;
		hex += 2;
	}
	return n;
}

static void report(const char *name, int ok)
{
	g_total++;
	if (!ok)
		g_fail++;
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

/* pass if got == expected over len bytes */
static void check_bytes(const char *name, const uint8_t *got,
                        const uint8_t *exp, size_t len)
{
	report(name, memcmp(got, exp, len) == 0);
}

/* ---- X25519: RFC 7748 section 5.2 ---------------------------------- */
static void test_x25519_scalarmult(void)
{
	uint8_t k[32], u[32], out[32], exp[32];

	puts("X25519 scalarmult (RFC 7748 sec 5.2):");

	hx(k, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
	hx(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
	hx(exp, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
	dossh_x25519(out, k, u);
	check_bytes("vector 1", out, exp, 32);

	hx(k, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
	hx(u, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
	hx(exp, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
	dossh_x25519(out, k, u);
	check_bytes("vector 2", out, exp, 32);
}

/* ---- X25519: RFC 7748 section 6.1 (Alice/Bob ECDH) ----------------- */
static void test_x25519_ecdh(void)
{
	uint8_t a[32], b[32], ka[32], kb[32], shared[32];
	uint8_t pubA[32], pubB[32], sA[32], sB[32];

	puts("X25519 ECDH (RFC 7748 sec 6.1):");

	hx(a,  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	hx(ka, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
	hx(b,  "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
	hx(kb, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
	hx(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

	dossh_x25519_public_key(pubA, a);
	check_bytes("Alice public key K_A", pubA, ka, 32);
	dossh_x25519_public_key(pubB, b);
	check_bytes("Bob public key K_B", pubB, kb, 32);

	dossh_x25519(sA, a, kb);            /* Alice: X25519(a, K_B) */
	check_bytes("Alice shared secret", sA, shared, 32);
	dossh_x25519(sB, b, ka);            /* Bob:   X25519(b, K_A) */
	check_bytes("Bob shared secret", sB, shared, 32);
}

/* ---- Ed25519: RFC 8032 section 7.1 --------------------------------- */
static void test_ed25519_one(const char *label,
                             const char *seed_hex, const char *pk_hex,
                             const char *msg_hex, const char *sig_hex)
{
	uint8_t seed[32], exp_pk[32], msg[64], exp_sig[64];
	uint8_t sk[64], pk[32], sig[64];
	size_t msg_len;

	hx(seed, seed_hex);
	hx(exp_pk, pk_hex);
	msg_len = hx(msg, msg_hex);
	hx(exp_sig, sig_hex);

	printf("Ed25519 %s (RFC 8032 sec 7.1):\n", label);

	dossh_ed25519_key_pair(sk, pk, seed);   /* seed is wiped by this call */
	check_bytes("derived public key", pk, exp_pk, 32);

	dossh_ed25519_sign(sig, sk, msg, msg_len);
	check_bytes("signature", sig, exp_sig, 64);

	report("verify good signature", dossh_ed25519_verify(sig, pk, msg, msg_len) == 0);

	/* flip one bit of the signature: verify must now reject */
	sig[10] ^= 0x40;
	report("reject tampered signature",
	       dossh_ed25519_verify(sig, pk, msg, msg_len) != 0);
}

static void test_ed25519(void)
{
	test_ed25519_one("TEST 1 (empty msg)",
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
		"55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
	test_ed25519_one("TEST 2 (1-byte msg)",
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		"72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
		"a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

/* ---- ChaCha20-Poly1305 AEAD: RFC 8439 section 2.8.2 ---------------- */
static void test_aead(void)
{
	uint8_t key[32], nonce[12], aad[16], plain[128], exp_ct[128], exp_tag[16];
	uint8_t ct[128], mac[16], dec[128];
	size_t plen, alen;

	puts("ChaCha20-Poly1305 AEAD (RFC 8439 sec 2.8.2):");

	hx(key,   "808182838485868788898a8b8c8d8e8f"
	          "909192939495969798999a9b9c9d9e9f");
	hx(nonce, "070000004041424344454647");
	alen = hx(aad, "50515253c0c1c2c3c4c5c6c7");
	plen = hx(plain,
		"4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
		"73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
		"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
		"637265656e20776f756c642062652069742e");
	hx(exp_ct,
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
		"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
		"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
		"3ff4def08e4b7a9de576d26586cec64b6116");
	hx(exp_tag, "1ae10b594f09e26a7e902ecbd0600691");

	dossh_aead_lock(ct, mac, key, nonce, aad, alen, plain, plen);
	check_bytes("ciphertext", ct, exp_ct, plen);
	check_bytes("tag", mac, exp_tag, 16);

	report("unlock recovers plaintext",
	       dossh_aead_unlock(dec, mac, key, nonce, aad, alen, ct, plen) == 0
	       && memcmp(dec, plain, plen) == 0);

	/* corrupt one ciphertext byte: unlock must fail authentication */
	ct[0] ^= 0x01;
	report("reject tampered ciphertext",
	       dossh_aead_unlock(dec, mac, key, nonce, aad, alen, ct, plen) != 0);
}

/* ---- SHA-256: NIST FIPS 180-4 examples ----------------------------- */
static void test_sha256_one(const char *label, const char *msg,
                            const char *exp_hex)
{
	uint8_t got[32], exp[32];
	hx(exp, exp_hex);
	dossh_sha256(got, (const uint8_t *)msg, strlen(msg));
	report(label, memcmp(got, exp, 32) == 0);
}

static void test_sha256(void)
{
	puts("SHA-256 (NIST FIPS 180-4):");
	test_sha256_one("\"abc\"", "abc",
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	test_sha256_one("448-bit two-block message",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	test_sha256_one("empty string", "",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

int main(void)
{
	puts("== DOSSH crypto known-answer tests ==");
	test_x25519_scalarmult();
	test_x25519_ecdh();
	test_ed25519();
	test_aead();
	test_sha256();
	printf("\n%d/%d vectors passed", g_total - g_fail, g_total);
	if (g_fail) {
		printf(", %d FAILED\n", g_fail);
		return 1;
	}
	puts(", all PASS");
	return 0;
}
