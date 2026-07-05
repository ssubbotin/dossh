/*
 * DOSSH random-number generator - a DOS entropy pool feeding a ChaCha20 DRBG.
 *
 * ===================================================================
 *  HONEST SECURITY WARNING - READ BEFORE RELYING ON THIS FOR SSH
 * ===================================================================
 * DOS has no operating-system entropy pool: there is no /dev/urandom, no
 * getrandom(2), no hardware RNG driver. This module does the best that can
 * honestly be done on a bare DOS box - it pools several individually WEAK
 * sources (a CPU cycle counter, the BIOS/RTC clocks, boot-time RAM contents,
 * and the timing jitter of interrupts and I/O), whitens them through SHA-256,
 * and stretches the result with a ChaCha20 DRBG. No single source here is
 * cryptographically strong; the design bets that combining and hashing many
 * weak sources yields enough unpredictability for key generation.
 *
 * This is STRICTLY WEAKER than a real OS CSPRNG. It has the same class of
 * caveat the SSH2DOS client shipped with ("the RNG is not cryptographically
 * secure"), though it is a good deal more careful. Any SSH server built on it
 * MUST ship as EXPERIMENTAL and say so to the operator. Do not overstate it:
 * on a freshly booted, idle, deterministic machine (e.g. a VM restored from a
 * snapshot) the early entropy can be poor, and a predictable host or session
 * key defeats the entire point of SSH. Gather over time, stir continuously,
 * and treat the first keys generated right after boot with suspicion.
 *
 * The DRBG construction itself (SHA-256 seed -> ChaCha20 fast-key-erasure
 * stream) is standard and testable; test/test_rng.c exercises it with a fixed
 * seed. What cannot be unit-tested is the QUALITY of the raw entropy - that is
 * the irreducible risk called out in docs/DESIGN-ssh.md sec 6.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_RNG_H
#define DOSSH_RNG_H

#include "crypto.h"   /* for DOSSH_FAR */

/*
 * Gather startup entropy into the pool and seed the DRBG. Call once, early,
 * before any key is generated (this seeds the persistent host key). Foreground
 * only - it reads the RTC/CMOS and samples RAM and may briefly mask interrupts.
 */
void DOSSH_FAR rng_init(void);

/*
 * Mix one weak sample into the entropy pool. THIS IS THE ONLY ISR-SAFE ENTRY
 * POINT: it touches static/DGROUP state only, takes the address of nothing,
 * calls no libc and nothing heavy, and tolerates the odd lost update - so it
 * is safe to call from the timer ISR and on packet / keystroke arrival, where
 * SS != DS. `sample` is any cheap datum whose low bits carry arrival timing
 * (a byte value, a ring index, a tick count); the routine additionally folds
 * in a fresh CPU cycle-counter reading, so the real entropy is the jitter
 * between successive calls, not `sample` itself.
 */
void DOSSH_FAR rng_stir(unsigned sample);

/*
 * Fill buf[0..n) with CSPRNG output (for ephemeral keys, nonces, cookies).
 * Foreground only. Auto-seeds via rng_init() on first use if needed, and folds
 * fresh pool state back in periodically for forward/backward secrecy.
 */
void DOSSH_FAR rng_bytes(unsigned char *buf, unsigned n);

/*
 * Fold the current entropy pool into the DRBG key. Called automatically by
 * rng_bytes over time; also exposed so the main loop can reseed on a schedule
 * (e.g. once a second from the tick handler's foreground tail). Foreground
 * only - it snapshots the pool with interrupts briefly masked.
 */
void DOSSH_FAR rng_reseed(void);

#ifdef DOSSH_RNG_TEST
/*
 * TEST-ONLY deterministic seeding hook (compiled only when DOSSH_RNG_TEST is
 * defined, i.e. never in the resident binary). Bypasses all hardware entropy
 * and seeds the DRBG purely from `seed`, resetting the block counter and
 * disabling auto-reseed, so the ChaCha20 DRBG becomes a deterministic stream
 * function of the seed. This is what makes the CSPRNG plumbing reproducible
 * under a known-answer test even though the raw entropy is not.
 */
void DOSSH_FAR rng_seed_for_test(const unsigned char *seed, unsigned n);
#endif

#endif /* DOSSH_RNG_H */
