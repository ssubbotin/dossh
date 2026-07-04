# DOSSH

**SSH-style remote access to a real-mode DOS PC** — see the screen and drive the
keyboard of a headless DOS machine over TCP/IP.

> **Status: resident and interactive (over serial).** `DOSSHD` installs as a
> TSR: the screen mirror and keyboard injection keep working while any
> separately launched program runs — including ones that write straight to
> video memory — proven end-to-end in QEMU. The network (packet-driver)
> transport is next. See [docs/DESIGN.md](docs/DESIGN.md) for the
> architecture.

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
    dossh (client)                   packet driver  ->  TCP
    renders 80x25 screen             scrape 0xB8000  ->  screen frames
    forwards keystrokes              inject keys     ->  BIOS kbd buffer
```

## Components

- **`DOSSHD.EXE`** — the DOS-side resident server (the "daemon").
- **`dossh`** — a small cross-platform client that renders the text screen in your
  terminal and forwards your keystrokes.

## Roadmap

- [x] **MVP:** foreground server, full-screen frames, keyboard injection, a
      `COMMAND.COM` session, and a custom client — proven in QEMU
      (serial transport; run `test/e2e-m2.py` to see it type by itself).
- [x] **TSR / background:** `DOSSHD` goes resident (`/S` status, `/U`
      uninstall) and mirrors/drives separately launched programs, including
      direct-video ones — `test/e2e-m3.py` proves it against a program that
      writes straight to `B800:0` and reads `INT 16h`.
- [ ] **Network transport:** TCP/UDP over a DOS packet driver instead of the
      serial port.
- [ ] **Screen diffing** and geometry-change handling.
- [ ] **Telnet/ANSI-compatible** mode (connect with a stock `telnet`/`nc`, no custom
      client needed).
- [ ] **MIT-clean TCP/IP layer** (see the licensing note in the design doc).
- [ ] Authentication; optional transport encryption.

## Building & testing

The target toolchain is **Open Watcom** (16-bit real mode), which cross-compiles
from Linux. Testing is done in **QEMU** with a well-supported DOS NIC
(NE2000 / PCnet / e1000) and its packet driver — real-hardware NIC support in DOS is
hit-or-miss, so the emulator is the reference environment.

See [docs/DESIGN.md](docs/DESIGN.md) for the full architecture, the interrupt and
memory details, and the wire-protocol sketch.

## License

MIT © 2026 Sergey Subbotin. See [LICENSE](LICENSE).
