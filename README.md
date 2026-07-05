# DOSSH

**SSH-style remote access to a real-mode DOS PC** — see the screen and drive the
keyboard of a headless DOS machine over TCP/IP.

> **Status: resident, interactive, networked, and speaks telnet.** `DOSSHD`
> installs as a TSR — the screen mirror and keyboard injection keep working
> while any separately launched program runs (including ones that write
> straight to video memory) — carries the session over **TCP via a DOS packet
> driver** (not just serial), and mirrors the screen as **ANSI over telnet**,
> so you connect with a stock `telnet`, `nc`, or PuTTY — **no custom client**.
> Proven end-to-end in QEMU **and on real hardware** — MS-DOS and FreeDOS, over
> an onboard Realtek RTL8168h. See [docs/DESIGN.md](docs/DESIGN.md) for the
> architecture and [docs/NETWORKING.md](docs/NETWORKING.md) to get it running on
> a real or emulated NIC.

## Why

If you have a real DOS machine — a vintage PC, an industrial controller, or a
modern box booted into DOS to run a low-level tool (a BIOS flasher, a hardware
diagnostic, a firmware updater) — there is no good way to operate it remotely.
You can watch it if you are standing in front of the monitor. That is it.

The existing DOS networking tools do not cover this:

- **mTCP** ships a Telnet *client*, not a server.
- The telnet "servers" you find run on **Linux** and serve a Linux shell *to* DOS
  clients — the opposite direction.
- **DSock**'s telnet-server example is licensed only for DM&P Vortex86 hardware.

`DOSSH` fills the gap: a small program that runs **on** the DOS box and lets you
reach it from anywhere on the network.

## What it does

`DOSSH` is really a **software KVM-over-IP for DOS text mode**:

- **Mirrors the screen.** It reads the VGA text buffer directly (`0xB8000`), so you
  see *whatever is on the screen* — including programs that write straight to video
  and never go through DOS or BIOS calls (BIOS flashers, installers, games). A plain
  telnet server cannot see those. DOSSH can.
- **Drives the keyboard.** Keystrokes from your client are injected into the BIOS
  keyboard buffer, so any running program receives them as if typed on the physical
  keyboard.
- **Stays out of the way.** It installs as a TSR and services the network from a
  timer interrupt, so it runs in the background while `COMMAND.COM` — or any other
  program — runs in the foreground. You are not limited to a captive shell; you
  control the whole machine.

```
   [ your laptop ]  ── TCP/IP ──▶  [ real DOS PC running DOSSHD.EXE ]
    telnet / nc / PuTTY              packet driver  ->  TCP (telnet)
    renders the ANSI screen          scrape 0xB8000  ->  ANSI diff stream
    sends keystrokes                 inject keys     ->  BIOS kbd buffer
```

## Components

- **`DOSSHD.EXE`** — the DOS-side resident server (the "daemon"). It speaks
  telnet/ANSI, so the client is whatever terminal you already have.

## Roadmap

- [x] **MVP:** foreground server, screen mirror, keyboard injection, a
      `COMMAND.COM` session — proven in QEMU over serial.
- [x] **TSR / background:** `DOSSHD` goes resident (`/S` status, `/U`
      uninstall) and mirrors/drives separately launched programs, including
      direct-video ones — `test/e2e-m3.py` proves it against a program that
      writes straight to `B800:0` and reads `INT 16h`.
- [x] **Network transport:** an in-house TCP/IP stack over a DOS packet driver
      (AMD PCnet), so a networked box is reachable from anywhere —
      `test/e2e-m5c.py` drives it over TCP.
- [x] **Telnet/ANSI console with screen diffing:** the mirror is a diff-driven
      ANSI stream and the network side negotiates telnet, so you connect with a
      stock `telnet`/`nc`/PuTTY — no custom client. Screen render, keystrokes,
      and the telnet path are covered by `test/e2e-m5a.py`, `e2e-m5b.py`,
      `e2e-m5c.py`, and the `test/test_ansikey.c` key-map unit test.
- [x] **MIT-clean TCP/IP layer** — a small purpose-built ARP/IP/TCP stack
      (`dosshd/net.c`), no third-party stack, so the release stays MIT.
- [ ] Authentication; optional transport encryption.

## Building & testing

The target toolchain is **Open Watcom** (16-bit real mode), which cross-compiles
from Linux. Testing is done in **QEMU**: the serial path over COM1, and the
network path over an emulated **AMD PCnet** NIC (`-device pcnet`) driven by the
`PCNTPK.COM` packet driver. PCnet is used because its driver transmits from
interrupt/TSR context (its send is a bus-master DMA hand-off); the NE2000's
shared programmed-DMA send does not — see [docs/DESIGN.md](docs/DESIGN.md) §13.

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, the interrupt and
memory details, and the wire-protocol sketch.

## License

MIT © 2026 Sergey Subbotin. See [LICENSE](LICENSE).
