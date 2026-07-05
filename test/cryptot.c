/*
 * CRYPTOT - DOS crypto self-test.
 *
 * A tiny real-mode program that links the -3 (386) crypto objects
 * (dosshd/crypto/*) into a small-model DOS EXE and runs a couple of the
 * official known-answer vectors, so the mixed 8086/386 build is proven to
 * compile AND link clean on the DOS target. The full vector suite runs
 * natively in test/test_crypto.c; this is just the on-target link/smoke proof.
 *
 * SSH-era feature: requires a 386 or better (the crypto is compiled -3), and a
 * 586 or better once the RNG smoke runs (RDTSC).
 *
 * Build: see dosshd/build.sh.  MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "rng.h"

static int fails = 0;

static void check(const char *name, const unsigned char *got,
                  const unsigned char *exp, int len)
{
	int ok = (memcmp(got, exp, len) == 0);
	if (!ok)
		fails++;
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

int main(void)
{
	unsigned char out[32];

	/* SHA-256("abc") = ba7816bf...20015ad  (NIST FIPS 180-4) */
	static const unsigned char sha_abc[32] = {
		0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,
		0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
		0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };

	/* X25519 first RFC 7748 sec 5.2 scalarmult vector */
	static const unsigned char k[32] = {
		0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,
		0x82,0x46,0x5e,0xdd,0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,
		0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4 };
	static const unsigned char u[32] = {
		0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,
		0x24,0xb1,0x5f,0x7c,0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,
		0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c };
	static const unsigned char x_exp[32] = {
		0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,
		0xf2,0x8d,0x08,0x4f,0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,
		0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52 };

	puts("== DOSSHD crypto self-test (386) ==");

	dossh_sha256(out, (const unsigned char *)"abc", 3);
	check("SHA-256 \"abc\"", out, sha_abc, 32);

	dossh_x25519(out, k, u);
	check("X25519 RFC 7748 5.2", out, x_exp, 32);

	/* RNG smoke: gather DOS entropy, seed the ChaCha20 DRBG, draw two blocks
	 * and confirm they are neither all-zero nor equal - proves rng.c compiled
	 * -3/-mm links and runs on target (RDTSC needs a 586+). */
	{
		unsigned char r1[32], r2[32];
		int i, allzero = 1, equal;
		rng_init();
		rng_bytes(r1, sizeof(r1));
		rng_bytes(r2, sizeof(r2));
		for (i = 0; i < 32; i++)
			if (r1[i]) { allzero = 0; break; }
		equal = (memcmp(r1, r2, 32) == 0);
		if (allzero || equal)
			fails++;
		printf("  [%s] RNG draws are nonzero and distinct\n",
		       (!allzero && !equal) ? "PASS" : "FAIL");
	}

	if (fails) {
		printf("%d self-test(s) FAILED\n", fails);
		return 1;
	}
	puts("crypto self-test PASS");
	return 0;
}
