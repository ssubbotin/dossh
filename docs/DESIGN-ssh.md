# DESIGN — SSH server mode for DOSSH (research + options)

**Status: research / design proposal. Nothing here is built.** This document
exists so the maintainer can decide *whether* and *how* to give DOSSH a real SSH
server, so a DOS box can be reached with a stock `ssh` client instead of
plaintext telnet. It ends with an explicit decisions list.

TL;DR: **for encryption, the tunnel DOSSH already ships is the correct answer**
(see [SECURITY.md](SECURITY.md)). A native in-DOS SSH server is *feasible* —
and, contrary to the project's earlier assumption, feasible **from the timer ISR
on the target hardware** — but it is a large, security-critical build whose
real liability is not CPU but **entropy**. Recommend it only if "ssh directly to
the box, no tunnel host on the LAN" is a hard product requirement.

---

## 1. What already exists (prior art)

| Project | What it is | Crypto runs where | License | Relevance |
|---|---|---|---|---|
| **SSHDOS** | SSH/SCP/SFTP **client** for DOS | on DOS (foreground, blocking) | GPL (WATTCP link conflict) | proves SSHv1 crypto ran on an 8086; a *client* |
| **SSH2DOS** (+ AnttiTakala / Toyoyo forks) | SSH **client** for DOS; forks added `aes128-ctr`, `hmac-sha2-256` (from PuTTY), and **AI-generated `curve25519-sha256` + `ssh-ed25519`** | on DOS, foreground, blocking, real-mode 8086+ | GPL-2.0 (+ PuTTY MIT, WATT-32, zlib parts) | **proves the modern primitives run in 16-bit real mode** — but README warns *"the RNG is not cryptographically secure at all — use at your own risk"* |
| **benjojo/dos_ssh** | "SSH **server** out of any INT 10h app" | **on the host, in Go** (`server.go`, `ssh.go`); DOS side only scrapes the screen and ships it over a link | — | The famous "DOS SSH server" **does its SSH crypto on a host, not on DOS.** It is a proxy. This is essentially our tunnel. |

Two conclusions:

1. **No real in-DOS SSH *server* exists.** The clients (SSHDOS, SSH2DOS) are
   foreground, blocking, and outbound — the opposite of DOSSH, which is a
   resident inbound server that mirrors *another* program's screen.
2. **The one well-known "DOS SSH server" (benjojo) terminates SSH on a host** and
   speaks a simple link to DOS. That is exactly the posture DOSSH already
   documents (`ssh -L` / a LAN SSH host). It validates option **C** below.

---

## 2. Correcting the core assumption

The project has carried the belief that *"SSH can't be done from the timer ISR
because the key-exchange handshake is a multi-second modexp."* **That was an
8086-era assumption and does not hold on the target hardware.**

- The real deployment target is a **modern Ryzen booted to DOS** (the uburyzen
  box), not an 8086. A curve25519 scalar-mult — the single most expensive step
  of a modern handshake — is **sub-millisecond** on a 4 GHz core even from
  unoptimized real-mode code. An ed25519 sign and a SHA-256 are cheaper still.
- The handshake is **not one long blocking call** anyway. Like our existing TCP
  handshake, it is a **multi-packet state machine**: receive `KEXINIT`, reply;
  receive the client's ephemeral key, compute the shared secret + exchange hash,
  reply `KEXDH_REPLY` + `NEWKEYS`. Each step is driven by an arriving packet and
  its crypto fits comfortably in one tick's budget on modern hardware.
- Therefore **SSH can be serviced from the ISR as a state machine, exactly like
  telnet is today** — no architecture "bypass" is required *on modern hardware*.

The "bypass the ISR where needed" idea only becomes necessary on genuinely slow
CPUs (a real 8086/286), where one scalar-mult *would* blow the tick budget. For
those, a deferred/foreground handshake (option B-slow) is the fallback. Given the
target is a Ryzen, we treat that as out of scope for a first cut.

**So the blocker was never CPU or memory. The blockers are (a) the sheer volume
of the SSH transport protocol and (b) entropy. See §5–6.**

---

## 3. Architectures

### A. Foreground SSH daemon (a separate program, not the TSR)

A normal `SSHD.EXE` that blocks freely, does the handshake and per-packet crypto
in its own main loop, and runs a shell.

- **Pro:** simplest to reason about; no ISR constraints at all.
- **Fatal con:** it **loses DOSSH's whole reason to exist.** DOSSH's headline is
  that a *resident* TSR mirrors and drives *a separately launched* foreground
  program — a BIOS flasher, an installer, whatever is on the screen. A
  foreground daemon can only serve *itself*; the moment the flasher runs, the
  daemon isn't running. **Rejected** as the primary design (it would be a
  different, lesser product).

### B. TSR with SSH in the ISR state machine (recommended if we build native)

Keep the resident architecture. Extend the existing per-connection state machine
(`net.c` owns TCP; `telnet.c` owns framing) with an **SSH transport layer** that
sits where telnet's IAC layer sits today:

```
 net.c (TCP, per-slot) ──▶ ssh.c (transport: framing, kex, cipher) ──▶ render/ansikey
                              └─ crypto.c (monocypher + sha256 + RNG)
```

- The handshake is a state machine fed by `net_rx_getc(i)`; each step's crypto
  runs inline (sub-ms on the Ryzen). No foreground helper, no INT 28h.
- Once `NEWKEYS` completes, every outbound screen packet is **encrypted per
  slot** and every inbound packet decrypted, inside the existing tick budget.
- **This preserves the TSR mirror-a-foreground-program ability** — the thing
  that makes DOSSH DOSSH.
- **Con:** it is the most code and the most security-critical (see §5–6), and it
  changes the multi-client broadcast (see §4).
- **B-slow fallback (only for real 8086/286):** if a single scalar-mult can't fit
  a tick, run the handshake in a foreground helper that the resident hands the
  raw TCP stream to for the duration of the handshake, then takes back with the
  negotiated session keys. Fragile (stream ownership handoff, reentrancy, the
  SS≠DS ISR trap, the private-stack rule for interrupt-time sends). Not needed on
  the target hardware; documented only for completeness.

### C. Host-side SSH termination (the tunnel — already shipped)

The client `ssh`es to a small capable host on the box's LAN (a Pi, the VPN
gateway, a jump box), which forwards plaintext telnet the last hop to DOSSHD.
This is `ssh -L 2323:<dosbox>:23 user@<lan-host>` — already documented in
[SECURITY.md](SECURITY.md), option A. **benjojo/dos_ssh is architecturally this.**

- **Pro:** SSH-grade encryption **today**, zero DOS-side crypto, zero new
  attack surface on the box, audited OpenSSH doing the crypto. Works with the
  existing telnet server unchanged, including multi-client and the password gate.
- **Con:** requires *a* capable host on the box's LAN (usually true — the box is
  rarely the only machine there), and it's "ssh to the *host*, telnet to the
  *box*," not "ssh to the box." For most real deployments this is invisible.

---

## 4. Interaction with existing features

- **Multi-client broadcast breaks its best optimization.** Today the ANSI diff
  stream is byte-identical to every client, so `net_tx_putc` broadcasts one byte
  to all send-rings. Under SSH, **each client has its own session keys**, so the
  same plaintext must be encrypted *N times* (once per slot's cipher state).
  Feasible on a Ryzen, but `net_tx_putc` can no longer be byte-identical —
  it becomes "render once, encrypt per ready slot." Per-slot cipher + sequence
  counters join `struct conn`.
- **Auth is replaced, not layered.** SSH has its own `userauth` (RFC 4252). The
  telnet password gate maps to SSH `password` auth; better, SSH enables
  **publickey** auth (an `authorized_keys`-style file on DOS) so no secret ever
  crosses the wire — a real upgrade over the cleartext telnet password.
- **Host key persistence.** Generate an `ssh-ed25519` host key once (first
  install), store it in a file (e.g. `DOSSHD.KEY` next to the EXE), load it
  resident. The client pins it in `known_hosts` normally.
- **Warm-reboot sentinel / render / NAWS** are all above the transport and are
  unaffected (they see plaintext after decryption), same as they see plaintext
  after IAC stripping today.

---

## 5. Crypto building blocks (licensing + real-mode fit)

**Use permissive primitives; never vendor a GPL SSH stack.** Dropbear
(MIT-ish, but ~110 KB and Linux) and wolfSSH (GPLv3/commercial) are out — wrong
size and/or license. SSH2DOS is GPL and its RNG is self-admittedly broken.

Recommended primitive set — all **MIT-compatible**:

| Need | Primitive | Source | License |
|---|---|---|---|
| KEX | `curve25519-sha256` | X25519 from **Monocypher** + a SHA-256 | CC0/BSD-2 + public-domain SHA-256 |
| Host key | `ssh-ed25519` | Ed25519 from **Monocypher** (uses SHA-512, included) | CC0/BSD-2 |
| Cipher/MAC | `chacha20-poly1305@openssh.com` **or** `aes*-ctr` + `hmac-sha2-256` | ChaCha20-Poly1305 from **Monocypher** | CC0/BSD-2 |

Monocypher is **~2000 lines, CC0-1.0 / BSD-2-Clause, no libc, no malloc** —
ideal license and footprint. It lacks SHA-256 (it has BLAKE2b + SHA-512), so add
a ~200-line public-domain SHA-256 for the `curve25519-sha256` exchange hash.
Choosing `chacha20-poly1305` as the cipher avoids needing a separate HMAC.

**Real-mode wrinkle to plan for:** Monocypher's field arithmetic is `uint64_t`
(radix 2^51). In 16-bit real mode every 64-bit op is a Watcom runtime call —
correct but bloated and slow. **Mitigation: build the crypto module for the 386
real-mode target (`-3`)** so it uses native 32-bit registers (operand-size
prefix works in real mode); it runs fine on the Ryzen and any 386+. That trades
away 8086 compatibility *for the SSH build only* — acceptable, since SSH is a
modern-box feature. (A fully 8086-native curve25519 with 16-bit limbs exists in
the SSH2DOS lineage but is GPL and unaudited; re-deriving one is extra work we
don't need for the Ryzen target.)

---

## 6. The real risk: entropy on DOS

This is the single biggest problem and the reason to be cautious.

SSH's security rests on **unpredictable ephemeral and host keys**. DOS has no
`/dev/urandom`, no OS entropy pool. SSH2DOS shipped with an RNG it openly calls
"not cryptographically secure at all." A weak RNG here doesn't degrade
gracefully — it can hand an eavesdropper the session key or let someone forge the
host key, defeating the entire point of adding SSH.

A defensible DOS entropy story would pool several weak sources and hash them:
`RDTSC` low bits sampled over time (the Ryzen has a cycle counter, readable in
real mode), timer-tick jitter, keystroke/packet-arrival timing, uninitialized
RAM at boot, the BIOS clock. This must be gathered at install (for the persistent
host key) **and** continuously during operation (for per-connection ephemerals),
then run through SHA-256/a CSPRNG (e.g. a ChaCha20-based DRBG). **Getting this
right — and being honest that it's weaker than a real OS RNG — is the crux.** It
should ship with an explicit experimental/caveat banner, like SSH2DOS's.

Second-order risk: a **hand-rolled SSH transport protocol is security-critical
surface.** RFC 4253 (transport), 4252 (auth), 4254 (connection/channels), packet
framing, MAC-then-encrypt ordering, rekeying, and dozens of interop quirks
against OpenSSH clients — this is where subtle, exploitable bugs live, and it's
far more code than the primitives.

---

## 7. Effort + phasing (if native SSH is chosen)

Rough order-of-magnitude on top of today's ~2 KLOC of DOSSH:

- **Primitives:** monocypher (~2 KLOC, vendored) + SHA-256 (~0.2 KLOC) + DRBG +
  entropy pool (~0.3 KLOC).
- **SSH transport (`ssh.c`):** framing, version exchange, `KEXINIT` negotiation,
  curve25519 kex, `NEWKEYS`, packet encrypt/decrypt, rekey — **~1.5–2.5 KLOC**
  and the bulk of the risk.
- **Auth + connection layer:** `userauth` (password + publickey), one
  `session` channel + `pty-req`/`shell` — **~0.5–1 KLOC**.
- **Integration:** per-slot cipher state in `net.c`, host-key gen/persist,
  wiring into the tick state machine.

Phasing:

1. **P1** — single client, `curve25519-sha256` + `ssh-ed25519` +
   `chacha20-poly1305`, `password` auth, one shell channel. Compiled `-3`. Ships
   behind an explicit "experimental, DOS-entropy caveat" flag. Prove a stock
   `ssh` connects and drives the box.
2. **P2** — `publickey` auth (`authorized_keys` on DOS) — removes the cleartext
   secret entirely.
3. **P3** — multi-client under SSH (per-slot encryption of the shared render
   stream), matching today's telnet multi-client.

A DGROUP note: DOSSH is at ~35.5 KB resident data of a 64 KB budget. Per-slot
cipher state, key material, and buffers for `NCONN` sessions plus the entropy
pool need a budget check early (P1 with a single session is comfortable; P3
multi-session needs measuring — the crypto *code* is in the code segment, but
per-session keys/IVs/rekey buffers live in DGROUP).

---

## 8. Recommendation

1. **For encryption specifically: use the tunnel that already ships.** It is
   SSH-grade, zero-risk, and requires no DOS crypto. Point users at
   [SECURITY.md](SECURITY.md) option A. This is honestly the right answer for the
   overwhelming majority of "I want it encrypted" cases, and it's what the one
   famous DOS-SSH-server (benjojo) actually does.
2. **Build native in-DOS SSH only if "ssh straight to the box, with no other
   host on its LAN" is a genuine product requirement.** If so, take architecture
   **B** (ISR state machine — the CPU is fast enough, and it keeps the TSR
   mirror), primitives from **Monocypher** (+ SHA-256), compiled `-3`, phased
   P1→P3, shipped with an explicit experimental/entropy caveat.
3. **Do not** build the foreground daemon (A) — it throws away DOSSH's purpose.

---

## 9. Open questions / decisions for the maintainer

1. **Is native SSH actually wanted, or does the tunnel suffice?** The tunnel
   already gives SSH-grade encryption today. Native SSH buys "ssh to the box with
   nothing else on its LAN" and a slicker UX — is that worth a large,
   security-critical build?
2. **Must the TSR mirror-a-foreground-program ability be preserved?** If yes
   (it's the product's whole point), the simple foreground daemon (A) is out and
   we commit to the harder ISR-state-machine path (B).
3. **Is the DOS-entropy caveat acceptable?** Native SSH on DOS will have a
   weaker RNG than a real OS and must ship as experimental. If that caveat is
   unacceptable for the project's posture, the tunnel is the answer and this
   stays unbuilt.
4. **Crypto-lib choice:** Monocypher (CC0/BSD-2, recommended) + a public-domain
   SHA-256 — confirm the license posture is fine for the MIT release, and accept
   building the crypto module for `-3` (386 real mode), dropping 8086
   compatibility for the SSH feature.
5. **Scope/phasing:** single-client password-auth P1 as a proof, or hold out for
   publickey + multi-client before shipping anything?
