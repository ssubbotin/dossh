/*
 * DOSSH random-number generator - implementation.
 *
 * A DOS entropy pool feeding a ChaCha20 DRBG. See rng.h for the honest
 * security warning: this is weaker than an OS CSPRNG and any SSH built on it
 * ships EXPERIMENTAL.
 *
 * Layout:
 *   - a small entropy POOL of DGROUP words, updated by rng_stir() (ISR-safe)
 *     and by the startup/continuous hardware gather (rng_init);
 *   - a ChaCha20 DRBG (32-byte key + 32-bit counter) reseeded from
 *     SHA-256(key || pool || counters); rng_bytes() is fast-key-erasure
 *     (each 64-byte ChaCha block rekeys the DRBG, giving backtracking
 *     resistance) and pulls the top 32 bytes of each block as output.
 *
 * All state is static (DGROUP). Built -mm -3 like the crypto module (it far-
 * calls dossh_sha256 / dossh_chacha20). See dosshd/build.sh.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <string.h>
#include "rng.h"
#include "crypto.h"

/* True only on the 16-bit DOS target (Open Watcom). On the native KAT host the
 * hardware sources are stubbed - the DRBG core is identical, and the fixed-seed
 * test hook exercises it deterministically. */
#if defined(__WATCOMC__) && defined(__I86__)
#  define DOSSH_RNG_DOS 1
#  include <i86.h>       /* MK_FP, _disable, _enable */
#  include <conio.h>     /* inp, outp                */
#else
#  define DOSSH_RNG_DOS 0
#endif

/* ---- hardware primitives (DOS only) -------------------------------- */

#if DOSSH_RNG_DOS
/*
 * Read the low 32 bits of the CPU time-stamp counter (RDTSC). Real-mode-legal
 * on a Pentium or better; DOSSH's crypto already requires a 386, so enabling
 * SSH effectively requires a 586+. Hand-encoded as bytes so it assembles under
 * any Open Watcom cpu setting:
 *     0F 31           rdtsc            ; EDX:EAX <- counter (EAX = low 32)
 *     66 89 C2        mov edx, eax     ; keep the low 32 in EDX
 *     66 C1 EA 10     shr edx, 16      ; so DX:AX == EAX (return in DX:AX)
 */
extern unsigned long rng_rdtsc(void);
#pragma aux rng_rdtsc =        \
    "0Fh 31h"                  \
    "66h 89h C2h"              \
    "66h C1h EAh 10h"          \
    value  [dx ax]             \
    modify [ax dx];

/* CMOS/RTC register read (index port 0x70, data port 0x71). */
static unsigned cmos_read(unsigned reg)
{
    outp(0x70, reg);
    return (unsigned)inp(0x71);
}
#else
/* Native fallback: a monotonically advancing counter so the plumbing runs;
 * NEVER a real entropy source (the native build exists only for the KAT). */
static unsigned long rng_rdtsc(void)
{
    static unsigned long t = 0;
    return t += 0x9E3779B1UL;   /* golden-ratio step, just to keep it moving */
}
#endif

/* ---- entropy pool -------------------------------------------------- */

#define POOL_WORDS 32                     /* DGROUP words of accumulator */
static volatile unsigned pool[POOL_WORDS];
static volatile unsigned pool_idx;
static volatile unsigned pool_stir;       /* count of stirs (also mixed in) */

/*
 * ISR-SAFE. Mix one weak sample plus a fresh cycle-counter reading into the
 * pool. Touches only static/DGROUP volatiles, takes no address of a local,
 * calls nothing that could deref an SS-relative pointer against DS, and does
 * no libc. A stir racing another stir can at worst lose an update - never
 * corrupt - which is acceptable for an entropy accumulator.
 */
void DOSSH_FAR rng_stir(unsigned sample)
{
    unsigned i = pool_idx & (POOL_WORDS - 1);
    unsigned t = sample ^ (unsigned)rng_rdtsc();   /* jitter = the real source */

    t += pool_stir;
    pool[i] += t;
    pool[i]  = (unsigned)((pool[i] << 7) | (pool[i] >> 9));  /* rotate-diffuse */
    pool[i] ^= t << 3;

    pool_idx  = i + 1;
    pool_stir = pool_stir + 1;
}

/* ---- ChaCha20 DRBG ------------------------------------------------- */

static unsigned char drbg_key[32];        /* current DRBG key (DGROUP)     */
static unsigned long drbg_ctr;            /* block/nonce counter, monotonic */
static unsigned long drbg_calls;          /* rng_bytes calls since reseed   */
static int           drbg_ready;          /* seeded?                        */
#ifdef DOSSH_RNG_TEST
static int           drbg_test_mode;      /* fixed-seed: disable auto-reseed */
#endif

/*
 * Fold the pool into the DRBG key: key <- SHA-256(key || pool || counters).
 * Foreground only; snapshots the pool with interrupts briefly masked so a
 * concurrent rng_stir cannot tear the copy.
 */
void DOSSH_FAR rng_reseed(void)
{
    static unsigned char material[32 + sizeof(pool) + 8];
    static unsigned char digest[32];
    unsigned long tick;
    unsigned n = 0;

    memcpy(material, drbg_key, 32);
    n = 32;

#if DOSSH_RNG_DOS
    _disable();
#endif
    memcpy(material + n, (const void *)pool, sizeof(pool));
    n += sizeof(pool);
    material[n++] = (unsigned char)pool_stir;
    material[n++] = (unsigned char)(pool_stir >> 8);
    material[n++] = (unsigned char)pool_idx;
    material[n++] = (unsigned char)(pool_idx >> 8);
#if DOSSH_RNG_DOS
    _enable();
#endif

    /* a couple more moving bytes: DRBG counter + a fresh cycle sample */
    material[n++] = (unsigned char)drbg_ctr;
    material[n++] = (unsigned char)(drbg_ctr >> 8);
    tick = rng_rdtsc();
    material[n++] = (unsigned char)tick;
    material[n++] = (unsigned char)(tick >> 8);

    dossh_sha256(digest, material, n);
    memcpy(drbg_key, digest, 32);

    memset(material, 0, sizeof(material));
    memset(digest, 0, sizeof(digest));
    drbg_calls = 0;
    drbg_ready = 1;
}

/*
 * Fill buf with CSPRNG output. Fast-key-erasure ChaCha20: each iteration
 * derives 64 keystream bytes, uses the first 32 to overwrite the DRBG key
 * (so past output cannot be recomputed) and the remaining 32 as output.
 * Foreground only.
 */
void DOSSH_FAR rng_bytes(unsigned char *buf, unsigned n)
{
    static unsigned char ks[64];
    unsigned char nonce[12];

    if (!drbg_ready)
        rng_init();

    while (n) {
        unsigned take = (n < 32) ? n : 32;

        memset(nonce, 0, sizeof(nonce));
        nonce[0] = (unsigned char)drbg_ctr;
        nonce[1] = (unsigned char)(drbg_ctr >> 8);
        nonce[2] = (unsigned char)(drbg_ctr >> 16);
        nonce[3] = (unsigned char)(drbg_ctr >> 24);

        dossh_chacha20(ks, drbg_key, nonce, 0, sizeof(ks));
        memcpy(drbg_key, ks, 32);        /* rekey: backtracking resistance */
        memcpy(buf, ks + 32, take);      /* output the upper half          */

        buf += take;
        n   -= take;
        drbg_ctr++;
    }
    memset(ks, 0, sizeof(ks));

    /* Fold fresh entropy back in periodically (skipped under the fixed-seed
     * test hook, which wants a deterministic stream). */
    drbg_calls++;
#ifdef DOSSH_RNG_TEST
    if (!drbg_test_mode && (drbg_calls & 0x3f) == 0)
        rng_reseed();
#else
    if ((drbg_calls & 0x3f) == 0)
        rng_reseed();
#endif
}

/* ---- startup entropy gather ---------------------------------------- */

void DOSSH_FAR rng_init(void)
{
    unsigned i;

    /* Cheap first: RDTSC sampled in a tight loop. The absolute values are
     * predictable but the inter-sample delta carries interrupt/DRAM-refresh
     * jitter, which is the point. */
    for (i = 0; i < 512; i++)
        rng_stir((unsigned)rng_rdtsc());

#if DOSSH_RNG_DOS
    {
        volatile unsigned char __far *p;

        /* BIOS timer tick (0040:006C) - a wall-clock word. */
        {
            unsigned long tk = *(volatile unsigned long __far *)MK_FP(0x40, 0x6C);
            rng_stir((unsigned)tk);
            rng_stir((unsigned)(tk >> 16));
        }

        /* RTC via CMOS: seconds, minutes, hours, day, month, year, and the
         * status/century bytes - low bits move, the rest is weak. */
        rng_stir(cmos_read(0x00));   /* seconds        */
        rng_stir(cmos_read(0x02));   /* minutes        */
        rng_stir(cmos_read(0x04));   /* hours          */
        rng_stir(cmos_read(0x06));   /* day of week    */
        rng_stir(cmos_read(0x07));   /* day of month   */
        rng_stir(cmos_read(0x08));   /* month          */
        rng_stir(cmos_read(0x09));   /* year           */
        rng_stir(cmos_read(0x32));   /* century        */
        rng_stir(cmos_read(0x0A));   /* status A (updating flag toggles) */

        /* Boot-time / uninitialized low RAM: the BIOS data area (0040:xx) and
         * the interrupt-vector table + boot leftovers at segment 0 vary from
         * machine to machine and boot to boot. Weak, but free. */
        p = (volatile unsigned char __far *)MK_FP(0x0040, 0);
        for (i = 0; i < 256; i++)
            rng_stir((unsigned)p[i]);
        p = (volatile unsigned char __far *)MK_FP(0x0000, 0);
        for (i = 0; i < 1024; i += 2)
            rng_stir((unsigned)p[i] | ((unsigned)p[i + 1] << 8));

        /* More RDTSC, now interleaved after the slow I/O above so the jitter
         * reflects real elapsed time. */
        for (i = 0; i < 512; i++)
            rng_stir((unsigned)rng_rdtsc());
    }
#endif

    rng_reseed();
}

/* ---- test-only deterministic seeding ------------------------------- */

#ifdef DOSSH_RNG_TEST
void DOSSH_FAR rng_seed_for_test(const unsigned char *seed, unsigned n)
{
    unsigned char digest[32];
    dossh_sha256(digest, seed, n);   /* fold any-length seed to a 32-byte key */
    memcpy(drbg_key, digest, 32);
    memset(digest, 0, sizeof(digest));
    drbg_ctr      = 0;
    drbg_calls    = 0;
    drbg_ready    = 1;
    drbg_test_mode = 1;
}
#endif
