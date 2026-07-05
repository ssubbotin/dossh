# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DOSSH is a KVM-over-IP for **real-mode DOS**: a resident TSR that scrapes the VGA
text screen at `0xB8000` and injects keystrokes into the BIOS type-ahead ring, so
it mirrors and drives *any* running DOS program (including ones that write straight
to video) over telnet or a **native SSH server that runs on the DOS box itself**.
It is 16-bit real-mode C + a little assembly, cross-compiled from Linux with Open
Watcom and tested in QEMU. Background: `README.md`, `docs/DESIGN.md`,
`docs/DESIGN-ssh.md`, `docs/NETWORKING.md`.

## Build

```sh
cd dosshd && ./build.sh        # WATCOM defaults to ~/tools/watcom; set WATCOM= to override
```

Produces two independent TSR binaries:

- **`DOSSHD.EXE`** — telnet/ANSI server, small model `-ms -0` (runs on an 8086).
  This is the baseline. Keep it **byte-for-byte unchanged** unless a change is
  genuinely for the telnet path (`md5sum` it before/after).
- **`DOSSHDS.EXE`** — the SSH build. All SSH code is behind `#ifdef DOSSH_SSH`; the
  base `.c` files are recompiled **medium model `-mm -3 -s`** and linked with
  `ssh.c`, `crypto/`, and `sshtramp.asm`. Requires a **Pentium/586+** at runtime
  (386 for the crypto, 586 for the RNG's `RDTSC`).

## Test

```sh
./test/run-tests.sh          # build + native unit tests + all QEMU e2e (slow)
./test/run-tests.sh unit     # native unit only (crypto/RNG KATs + ansikey), fast, no QEMU
./test/run-tests.sh ssh      # native SSH interop vs a real OpenSSH client (needs ssh + sshpass)
python3 test/e2e-m5c.py      # run a single e2e directly
```

- **e2e tests share one floppy image (`test/work/dosshd.img`) — run them
  SEQUENTIALLY.** Parallel runs race on `mcopy` and fail to boot.
- The e2e floppy is **FreeDOS** (fetched on first run). SSH is also proven on
  **MS-DOS 6.22** via `MSDOS_IMG=/path/to/622.img python3 test/e2e-ssh-msdos.py`
  (self-skips without an image; 6.22 isn't redistributable, so it stays out of CI).
- Boot a box to poke by hand: `test/qemu-run.sh`. Env knobs: `TRANSPORT`
  (`serial`|`pkt`|`ssh`|`sshser`), `PORT`, `PW=<pw>` (`/P:`), `EOF=1` (`/EOF`),
  `AUTHKEYS_SRC=<pubkey file>` (SSH publickey), `MON=<unix sock>` (QEMU monitor for
  `xp/…xb 0xb8000` VRAM dumps — the go-to debugging move), `QEMU_ACCEL` (`kvm:tcg`).
- Lint mirrors CI: `shellcheck` on shell scripts, `ruff --select E9,F test/`.

## Architecture

The **tick ISR** (`INT 1Ch`, in `dosshd.c`) is the engine: every timer tick it
services the network, pulls diffed screen bytes, and pumps keystrokes — all
**DOS-call-free** (port I/O, far memory, the packet driver only), so it is safe
regardless of what the foreground program is doing (the InDOS/reentrancy trap
never applies). Lifecycle (`/S` status, `/U` uninstall) goes through an `INT 2Fh`
multiplex handler (`AH=D5h`).

The data path is layered, each layer swappable:

- **`net.c`** — an in-house, MIT-clean ARP/IP/TCP stack over a Crynwr packet
  driver. `struct conn conns[NCONN]` holds per-slot TCP state; multi-client is a
  `(sport,srcip)` demux with one broadcast screen + a merged keyboard. Exposes a
  byte-stream link API (`net_rx_getc(i)`, `net_tx_putc`, `net_take_new_slot`, …).
  Serial/COM1 is the alternate transport.
- **`render.c`** — diffs `0xB8000` against a shadow and emits ANSI (CUP/SGR,
  CP437→UTF-8 via generated `cp437.c`). One shadow, one diff stream, shared by all
  clients.
- **`ansikey.c`** — maps raw terminal bytes (ASCII/CSI/SS3/telnet CR-LF) to BIOS
  scancodes injected into the type-ahead ring. Single input choke point; the
  warm-reboot sentinel (`0x1E` ×3 then `Y`) lives here.
- **Framing** sits between `net.c` and render/ansikey: **`telnet.c`** (telnet IAC +
  NAWS) or **`ssh.c`** (a byte-fed SSH-2.0 state machine — version exchange,
  KEXINIT, curve25519 kex, NEWKEYS, password/publickey userauth, one session
  channel). Both expose the same channel interface so the tick pumps either.
- **`crypto/`** (SSH only) — vendored **Monocypher** + a public-domain SHA-256 +
  `rng.c` (an `RDTSC`/RTC/boot-RAM entropy pool → ChaCha20 DRBG). `sshtramp.asm`
  switches SS:SP to a private DGROUP stack so the crypto's near-data stack buffers
  resolve at interrupt time.

## Non-obvious constraints (violating these produces baffling, silent bugs)

- **Watcom SS≠DS in `__interrupt` handlers.** An ISR runs with `SS != DS`, so
  passing `&local` to any function that dereferences it (it derefs DS-relative, but
  the local is on SS) writes to the wrong segment. In ISR-reachable code: **no
  `&local` out-params** — use `static` DGROUP buffers or return-by-value. Has bitten
  `net.c`, `render.c`, and `net_release`; grep the `static`-REGS comments.
- **DGROUP is 64 KB and the SSH build is against the ceiling (~60 KB).** Per-slot
  SSH state (keys/IVs/seq) is replicated; transient scratch is *shared* statics, not
  per-slot. `NCONN` is 2 for SSH, 3 for telnet. Check the `.map` after state changes.
- **Interrupt-time send needs a bus-master NIC.** AMD PCnet (`PCNTPK.COM`) transmits
  from the tick; NE2000 cannot (CF=0 but nothing goes out at interrupt time). Tests
  use `-device pcnet`.
- **The SSH build is compiled `-s` (no stack-overflow check) deliberately.** The
  hand-switched DGROUP stack in `sshtramp.asm` makes Watcom's `__STK` check
  false-fire against the *original* stack limit ("Stack Overflow!" at install); `-s`
  removes the bogus check.
- **`pkill -f qemu-system-i386` self-matches** when the same shell command also
  contains the `qemu-system-i386` launch string. Kill QEMU by PID (from `ss`), or
  keep the kill in a command separate from the launch.
- **The SSH handshake takes ~15–20 s under QEMU/TCG** (sub-ms on real hardware — the
  crypto runs on the *emulated* CPU). SSH e2e attempts need generous timeouts; a
  client killed mid-handshake wedges the single-slot server.

## Git

- Commit as `Sergey Subbotin <ssubbotin@gmail.com>`. Do not mention
  reverse-engineering in code, comments, or commit messages.
- **This repo credits Claude Code as a co-author** (the maintainer opted in at 1.0):
  append `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` to commits — this
  intentionally overrides the global "no AI attribution" rule *for this project*.
- Milestones are tagged `vX.Y.Z`; pushing a `v*` tag triggers
  `.github/workflows/release.yml` to cross-build and attach both EXEs.
