/*
 * Tests for the DOSSH RNG (dosshd/crypto/rng.c): a DOS entropy pool feeding a
 * ChaCha20 DRBG.
 *
 * Runs NATIVELY (cc on Linux). It links the very same rng.c + crypto the DOS
 * build uses, compiled with -DDOSSH_RNG_TEST so the deterministic seeding hook
 * (rng_seed_for_test) is available.
 *
 * What is - and is not - testable:
 *   - The DRBG construction (SHA-256 seed -> ChaCha20 fast-key-erasure stream)
 *     IS deterministic and reproducible, so we KAT it: a fixed seed yields the
 *     same stream every time and a fixed golden vector; two different seeds
 *     diverge. This proves the CSPRNG plumbing.
 *   - The raw ENTROPY QUALITY is NOT unit-testable on DOS - that is the
 *     irreducible risk documented in rng.h and docs/DESIGN-ssh.md sec 6. We
 *     only sanity-check that the DRBG's *output* is well distributed.
 *
 * Prints PASS/FAIL per check and exits nonzero on any failure.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>
#include <string.h>

#include "../dosshd/crypto/rng.h"

static int g_fail = 0;
static int g_total = 0;

static void report(const char *name, int ok)
{
    g_total++;
    if (!ok)
        g_fail++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

static void hexline(const char *label, const unsigned char *b, unsigned n)
{
    unsigned i;
    printf("%s: ", label);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

/* ---- DRBG known-answer / determinism ------------------------------- */

/* Golden first-32-bytes of the DRBG stream for seedA below. This pins the
 * exact construction (SHA-256(seed) -> ChaCha20 fast-key-erasure); it is
 * model-independent because the fixed-seed path never touches the pool. */
static const unsigned char golden[32] = {
    0xe1,0x61,0x53,0x68,0x36,0xce,0x0c,0xa1,0x5d,0x6e,0x3d,0x7c,0xda,0x51,0x7d,0x31,
    0xd2,0xe5,0x2d,0x0a,0xe9,0x05,0x17,0x90,0xa0,0x20,0x0f,0x2e,0x84,0x5c,0x0c,0x21
};

static void test_drbg_kat(void)
{
    static const unsigned char seedA[] = "DOSSH RNG KAT seed A";
    static const unsigned char seedB[] = "DOSSH RNG KAT seed B";
    unsigned char a[256], b[256], c[256];
    unsigned i, diff;

    puts("DRBG determinism / KAT (fixed seed, hardware entropy bypassed):");

    /* same seed -> identical stream, twice */
    rng_seed_for_test(seedA, sizeof(seedA) - 1);
    rng_bytes(a, sizeof(a));
    rng_seed_for_test(seedA, sizeof(seedA) - 1);
    rng_bytes(b, sizeof(b));
    report("fixed seed reproduces the stream", memcmp(a, b, sizeof(a)) == 0);
    hexline("    seedA stream[0..32)", a, 32);

    report("stream matches golden KAT vector", memcmp(a, golden, 32) == 0);

    /* different seed -> divergent stream */
    rng_seed_for_test(seedB, sizeof(seedB) - 1);
    rng_bytes(c, sizeof(c));
    hexline("    seedB stream[0..32)", c, 32);
    report("different seed diverges from seedA", memcmp(a, c, sizeof(a)) != 0);

    /* the two streams should differ in essentially every byte, not just one */
    diff = 0;
    for (i = 0; i < sizeof(a); i++)
        if (a[i] != c[i])
            diff++;
    report("seedA vs seedB differ in > 90% of bytes", diff > (sizeof(a) * 9) / 10);
}

/* ---- output distribution sanity ------------------------------------ */

#define SANE_N 65536u

static void test_output_sanity(void)
{
    static unsigned char buf[SANE_N];
    static unsigned char prev[32], cur[32];
    unsigned long counts[256];
    unsigned long sum;
    unsigned i, distinct, mn, mx, consec_equal;
    double chi2, expct, mean;

    puts("Output distribution sanity (real path: rng_init -> DRBG):");

    /* Exercise the real code path (gather + reseed + fast-key-erasure). On the
     * native host the hardware sources are stubbed, so this is a distribution
     * check on the DRBG whitening, not an unpredictability claim. */
    rng_init();

    /* pull the whole sample in modest chunks (also exercises many calls +
     * the periodic auto-reseed) */
    for (i = 0; i < SANE_N; i += 256)
        rng_bytes(buf + i, 256);

    /* not constant */
    {
        int constant = 1;
        for (i = 1; i < SANE_N; i++)
            if (buf[i] != buf[0]) { constant = 0; break; }
        report("output is not constant", !constant);
    }

    /* histogram */
    memset(counts, 0, sizeof(counts));
    for (i = 0; i < SANE_N; i++)
        counts[buf[i]]++;

    distinct = 0;
    mn = 0xffffffffu; mx = 0;
    for (i = 0; i < 256; i++) {
        if (counts[i])
            distinct++;
        if (counts[i] < mn) mn = (unsigned)counts[i];
        if (counts[i] > mx) mx = (unsigned)counts[i];
    }
    report("every byte value 0..255 appears", distinct == 256);
    printf("    distinct values=%u  min bin=%u  max bin=%u  (expected/bin=%u)\n",
           distinct, mn, mx, (unsigned)(SANE_N / 256));

    /* mean should sit near 127.5 */
    sum = 0;
    for (i = 0; i < SANE_N; i++)
        sum += buf[i];
    mean = (double)sum / (double)SANE_N;
    report("byte mean within [120,135] of 127.5", mean >= 120.0 && mean <= 135.0);
    printf("    byte mean=%.3f\n", mean);

    /* Pearson chi-square vs uniform; 255 dof. A healthy uniform source lands
     * near 255 and almost never outside ~[160,360]; we use generous bounds so
     * the check flags gross bias without flaking. */
    expct = (double)SANE_N / 256.0;
    chi2 = 0.0;
    for (i = 0; i < 256; i++) {
        double d = (double)counts[i] - expct;
        chi2 += (d * d) / expct;
    }
    report("chi-square in [150,400] (255 dof)", chi2 >= 150.0 && chi2 <= 400.0);
    printf("    chi-square=%.1f\n", chi2);

    /* consecutive rng_bytes() results differ */
    rng_bytes(prev, sizeof(prev));
    consec_equal = 0;
    for (i = 0; i < 64; i++) {
        rng_bytes(cur, sizeof(cur));
        if (memcmp(prev, cur, sizeof(cur)) == 0)
            consec_equal++;
        memcpy(prev, cur, sizeof(cur));
    }
    report("64 consecutive 32-byte draws are all distinct", consec_equal == 0);
}

int main(void)
{
    puts("== DOSSH RNG tests (ChaCha20 DRBG over a DOS entropy pool) ==");
    test_output_sanity();
    test_drbg_kat();
    printf("\n%d/%d checks passed", g_total - g_fail, g_total);
    if (g_fail) {
        printf(", %d FAILED\n", g_fail);
        return 1;
    }
    puts(", all PASS");
    return 0;
}
