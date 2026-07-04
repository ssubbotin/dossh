# DOSSH — Design & Analysis

## 1. Goal

Run a small resident program on a real-mode DOS PC that lets an operator, from
anywhere on the network, **see the machine's text screen live and drive its
keyboard** — so any DOS program (`COMMAND.COM`, a BIOS flasher, an installer, a
diagnostic) can be watched and controlled remotely, exactly as if sitting at the
console.

It is not a captive "shell" in the Unix sense. It is closer to a **software
KVM-over-IP for DOS text mode**: mirror the console, inject keystrokes, stay
resident.

## 2. Why the obvious approaches are not enough

A telnet-style server that pipes `stdin`/`stdout` only captures output written
through DOS (`INT 21h`) or BIOS TTY (`INT 10h/0Eh`) calls. Most interesting
low-level DOS programs — BIOS flashers included — **write directly to video memory**
and read the keyboard through `INT 16h` or the raw port. A pipe-based server sees a
blank session for those.

To be useful for the motivating case (watching a firmware updater run on a headless
box), the server must capture the **actual screen contents**, not a byte stream.

## 3. Architecture

```
+------------------------- DOS PC (DOSSHD.EXE, resident) --------------------------+
|                                                                                  |
|   timer ISR (INT 1Ch)  --------+                                                 |
|                                |  poll                                           |
|   packet driver (INT 60h) <----+----> TCP/IP layer  <----> connection state      |
|            ^                                   |                                  |
|            | rx/tx frames                      | screen frames / key events      |
|            v                                   v                                  |
|   RTL/NE2K/PCnet NIC                    +-------------------+                     |
|                                         | screen mirror     | read 0xB8000        |
|                                         | (0xB800 scraper)  | (80x25x2 = 4000 B)  |
|                                         +-------------------+                     |
|                                         | keyboard injector | write BIOS buffer   |
|                                         | (0x40:1A/1C/1E)   | 0040:001E ring      |
|                                         +-------------------+                     |
+----------------------------------------------------------------------------------+
                                   |  TCP/IP
                                   v
+---------------------------------- client -------------------------------------+
|  dossh: connect, render 80x25 (CP437 -> Unicode, VGA attrs -> ANSI colors),   |
|         capture local keys, send key events                                   |
+-------------------------------------------------------------------------------+
```

## 4. Screen mirroring

- Colour text mode (mode 03h) stores the screen at physical **`0xB8000`**
  (segment `B800h`). Layout is `rows x cols` cells of 2 bytes: byte 0 = character
  (code page 437), byte 1 = attribute (bits 0-3 fg, 4-6 bg, 7 blink/intensity).
- Standard geometry is **80x25** (4000 bytes), but 80x43/80x50 and 40-column modes
  exist. The scraper reads the current mode and dimensions from the BIOS Data Area
  (`0040:0049` mode, `0040:004A` columns, `0040:0084` rows-1) so it adapts.
- The **cursor** position comes from the BDA (`0040:0050`) or the CRTC (ports
  `3D4h/3D5h`, registers 0Eh/0Fh); cursor visibility/shape from CRTC 0Ah/0Bh.
- **Diffing:** keep the last frame sent; each tick, compare the live buffer and send
  only changed spans (run-length by row). A full 80x25 frame is 4000 bytes, so even
  a full resend a few times a second is cheap; diffing keeps it tiny for a mostly
  static screen.
- **Snow / tearing** is a non-issue on anything past the original CGA; we read the
  buffer directly without waiting for retrace.

Monochrome text mode uses `0xB0000` (segment `B000h`); the scraper picks the base
from the video mode.

## 5. Keyboard injection

Two options; we plan to support both, defaulting to the buffer poke:

1. **BIOS keyboard buffer poke.** The BIOS type-ahead ring lives at `0040:001E`
   (16 words), with head `0040:001A` and tail `0040:001C`. Writing a
   `(scancode<<8 | ascii)` word at the tail and advancing it makes any program that
   reads via `INT 16h` (including `COMMAND.COM`) receive the key. Must be done with
   interrupts disabled to stay consistent with a real keystroke arriving.
2. **`INT 16h` hook.** For programs that poll the hardware or want richer key state,
   hooking `INT 16h` lets us satisfy reads from a network-fed queue.

The client sends key events as `(scancode, ascii, modifiers)`; a small translation
table maps terminal input to BIOS scancode/ascii pairs (including function keys,
arrows, and the flags AFUDOS-style tools expect).

## 6. Residency and servicing the network

`DOSSHD.EXE` installs as a **TSR** and hooks the **timer tick** (`INT 1Ch`, ~18.2 Hz,
optionally reprogrammed faster) to get periodic control while a foreground program
runs. On each tick it:

1. services the packet driver (drain received frames, run the TCP state machine,
   flush pending tx),
2. injects any queued keystrokes,
3. scrapes the screen and, if the connection is idle enough, sends a diff.

The hard parts are **reentrancy and DOS-unsafety inside an ISR**: we must not call
`INT 21h` from the tick handler while DOS is busy (check the DOS "InDOS" flag and
the critical-error flag, and defer if unsafe). Network buffers, the TCP state, and
the screen scraper are all DOS-call-free, which keeps the ISR path safe; anything
needing DOS is queued for a foreground hook.

Packet drivers deliver receives via an application callback, which composes cleanly
with a tick-driven poller.

## 7. Transport and the MIT question

DOSSH needs a TCP/IP layer over a packet driver. The candidates:

| Option | Pros | Cons |
| --- | --- | --- |
| **mTCP** | mature, small, well documented | custom (non-MIT) license — cannot be re-licensed MIT |
| **Watt-32 / WATTCP** | feature-rich | heavier; licensing not MIT-clean |
| **from-scratch minimal TCP** | fully MIT, tiny, tailored | must implement ARP/IP/TCP + retransmit |

To keep the released tool **cleanly MIT-licensed**, the plan is a **small,
purpose-built TCP/IP layer** (single listening socket, one active connection, basic
retransmit/rwnd — a few hundred lines over the packet-driver API). It only has to
carry one interactive stream, so it can be far smaller than a general stack. mTCP is
used **only as a reference / early prototype**, never redistributed.

## 8. Wire protocol (sketch — historical)

> **Superseded by §14.** M1–M4 implemented the binary `SCREEN`/`KEY` framing
> below (see `docs/PROTOCOL.md`); M5 replaces it with a telnet/ANSI console. The
> sketch is kept for context.

Binary, length-prefixed frames. Server -> client:

- `HELLO` — cols, rows, mode, protocol version.
- `SCREEN` — list of `(row, col, len, cells[])` runs (each cell = char + attr).
- `CURSOR` — row, col, visible, shape.
- `BELL`, `MODE` (geometry change), `BYE`.

Client -> server:

- `KEY` — scancode, ascii, modifiers.
- `PING` / `RESIZE-ACK` / `BYE`.

A second, optional **ANSI mode** re-expresses `SCREEN`/`CURSOR` as ANSI escape
sequences so a stock `telnet`/`nc` shows a live (if less efficient) screen with no
custom client.

## 9. Client

A small cross-platform client (Python first, for speed of iteration) that:

- renders the 80x25 grid in the local terminal, mapping **CP437 -> Unicode** and
  **VGA attributes -> ANSI colours**,
- puts the terminal in raw mode and forwards keystrokes as `KEY` events,
- reconnects and redraws on demand.

## 10. Build & test

- **Toolchain:** Open Watcom C/C++ (16-bit real mode, `wcl -bt=dos`), which builds
  DOS binaries from Linux. TSR + interrupt work needs real-mode 16-bit, so DJGPP
  (32-bit protected mode) is not the fit for the resident core.
- **Reference environment:** QEMU with an emulated **NE2000 / PCnet / e1000** NIC and
  its DOS packet driver (these have solid DOS drivers, unlike many modern Realtek
  parts). DOSBox-X is a secondary sanity check.
- **Loopback of the concept** is testable entirely in a VM before any hardware.

## 11. Milestones

1. **M1 — screen scraper + client, no residency.** *(done)* Foreground program
   that sends full 80x25 frames over serial, and a Python client that renders
   them. Prove the mirror.
2. **M2 — keyboard injection.** *(done)* Client keys reach `COMMAND.COM`. Now it
   is interactive.
3. **M3 — TSR + tick servicing.** *(done)* Background operation; control a
   separately launched program (the real goal — watch a flasher run).
   `DOSSHD` goes resident with an INT 2Fh presence/uninstall handshake;
   `/S`/`/U` manage it.
4. **M4 — packet-driver transport + MIT TCP layer.** *(done — see §13.)* An
   in-house ARP/IP/TCP stack over an AMD PCnet packet driver; the TSR services
   sends from the timer ISR on a private stack.
5. **M5 — telnet/ANSI console + cell-diffing.** *(next — see §14.)* Become a
   telnet/ANSI terminal server (stock `telnet`/`nc`/PuTTY, no custom client),
   diff-driven; retires the binary protocol and the Python client.
6. **M6 — auth**, optional transport encryption; geometry/mode polish.

## 12. Risks & open questions

- **ISR safety** around DOS reentrancy is the main engineering risk; mitigated by
  keeping the tick path DOS-call-free and deferring anything else.
- **Snow-free direct reads** are fine on VGA; CGA-era machines may want retrace
  timing (low priority).
- **Graphics modes** are out of scope for v1 (text mode only); a later version could
  send raw framebuffer tiles.
- **Security:** the transport is unauthenticated and unencrypted initially. This is
  documented loudly; auth and an optional cipher are on the roadmap. Not for hostile
  networks yet.

## 13. M4 — network transport (concrete design)

M4 replaces the serial byte stream with **TCP over a DOS packet driver**, so a
headless networked DOS box is reachable from anywhere — the motivating case.

**Transport seam.** The framing code (`start_frame`/`tx_pump` on the way out,
`rx_byte` → `inject_key` on the way in) is decoupled from the byte transport
behind a small `link` interface (`link_init`, `link_tx_ready`, `link_putc`,
`link_poll`, `link_getc`). Serial and packet transports are two implementations
selected at build time (`-DLINK_PKT`); the wire protocol and the **entire Python
client are unchanged**. This keeps the M1–M3 serial path and its tests working.

**Why TCP, not UDP.** TCP keeps the client and the DSSH byte-stream protocol
frozen (the client already speaks TCP), delivers keystrokes reliably, and
segments the 4 KB screen frames for free — UDP would force datagram
sub-framing plus a key-ack layer and would change the client. The cost is a
single-socket TCP state machine in the server, scoped small (§7): listen, one
connection, three-way handshake, in-order stream, checksums, ACKs, and a dumb
retransmit timer on the timer tick. No general windowing.

**Stack (DOS side, all in the TSR, tick-serviced, DOS-call-free).**

- **Packet driver** — locate it by scanning INT 0x60–0x7E for the `"PKT DRVR"`
  signature; `get_address` for our MAC; `access_type` for ETH_P_IP and
  ETH_P_ARP; `send_pkt` to transmit; a `receiver` callback (packet-driver
  register convention) copies incoming frames into a small RX ring. The
  callback runs in the NIC IRQ; the tick drains the ring.
- **ARP** — reply to requests for our IP; learn the peer's MAC from the
  Ethernet header of frames it sends (a reply-only server needs little else).
- **IP** — parse/build with header checksum; static address for v1 (DHCP
  later).
- **TCP** — the single socket described above, feeding the `link` byte API.

**Config.** Static IP + listen port, defaulting to the QEMU user-net guest
(`10.0.2.15`, gateway `10.0.2.2`), overridable on the command line.

### 13.1 Interrupt-time send: the hard part, and the fix

A TSR has no foreground of its own — it services the network from the timer
ISR. Calling the packet driver's `send_pkt` at *interrupt time* is the crux,
and it took real work to get right. Two independent obstacles, both proven
with QEMU packet captures (`-object filter-dump`):

1. **The NIC/driver must do a "blind" transmit.** The **NE2000 (Crynwr
   `NE2000.COM`)** send copies the frame to the card through the 8390's
   *shared programmed remote-DMA window* — the same register path its receive
   up-call uses. Issued from the timer ISR it returns success (CF=0) but
   transmits nothing, and corrupts the NIC. This is architectural to the 8390;
   no 8390 driver avoids it. **AMD PCnet (`PCNTPK.COM`)** instead does a
   bus-master DMA hand-off: fill a host-RAM TX descriptor, poke `CSR0=TDMD`,
   return — the TX-complete IRQ is never waited on, and there is no shared DMA
   window. PCnet transmits fine from the ISR. (Precedent: `rmtdos`, a TSR twin
   of DOSSHD, streams the screen over Ethernet from the IRQ0 tick.)

2. **`send_pkt` must run on a real stack.** Even with PCnet, a send issued on
   the tiny interrupted DOS stack silently fails (CF=0, nothing transmitted).
   `pkt_send` therefore switches `SS:SP` to a private multi-KB DGROUP stack —
   and *only* the driver `INT` runs there (interrupts disabled, rmtdos-style),
   never a C call — reaching the driver through its IVT vector so no fixed INT
   opcode is baked in. See `dosshd/pktrecv.asm:pkt_send_bigstack`. The single
   non-reentrant tick is the sole caller of `send_pkt`; the receive up-call
   only stages a frame, never sends.

### 13.2 Test harness

QEMU `-device pcnet` (PCI Am79C970A) driven by AMD **`PCNTPK.COM`**
(`PCNTPK INT=0x60`; it auto-detects the PCI NIC). QEMU `-netdev user` with
`hostfwd=tcp::PORT-:10.0.2.15:PORT` maps a host port to the guest listener, so
the existing client and E2E scripts connect to `127.0.0.1:PORT` exactly as
before. `qemu-run.sh` gains a `TRANSPORT=pkt` mode (adds the NIC + hostfwd and
loads PCNTPK before DOSSHD); serial stays the default. The driver is fetched
at test time (`amdnic_2.zip`, freely redistributable — a separate tool, never
linked into MIT DOSSHD). Proven end-to-end by `test/e2e-m4.py`: TCP handshake,
live screen stream, and remote key injection, all from the TSR over the wire.

## 14. M5 — telnet/ANSI console (supersedes the binary protocol)

M5 turns DOSSH into a **telnet/ANSI terminal server** for the DOS text screen:
any stock `telnet` / `nc` / PuTTY over the network transport, or any serial
terminal over COM1, shows the live screen and types into it — **no custom
client**. This *retires* the binary `SCREEN`/`KEY` framing of §8 and the Python
`client/dossh`. The mechanism underneath — screen scrape, BIOS key injection,
serial + packet-driver transports, TSR residency, `/S`/`/U` — is unchanged; only
the wire format above the transport changes. Rationale: for a text-mode screen
over TCP, diff-driven ANSI is nearly as compact as the binary protocol and
carries the screen faithfully (16 colours, blink, CP437 box-drawing), while a
telnet server needs no install and matches the "reach a headless box from
anywhere" goal. (SSH is impractical for a real-mode TSR — crypto is too heavy.)

**Rendering — diff-driven ANSI.** Keep a `shadow[4000]` copy of the last-drawn
80×25 screen. Each tick, one pass diffs live VRAM against the shadow (updating it
in the same pass) and emits ANSI for changed cells: `ESC[row;colH`, an SGR only
when the VGA attribute changes, then the character(s); changed spans ≤3 cells
apart are coalesced. Output is paced at ~512 bytes/tick. A **full repaint**
(`ESC[?25l` `ESC[2J` `ESC[H` + every cell, resumable across ticks) is sent on:
connect (TCP rising edge), a serial-only ~2 s cadence (a mid-stream serial
terminal resyncs), geometry/mode change, and as a fallback when >75 % of cells
changed (CLS/scroll — cheaper and self-syncing). After each batch the terminal
cursor is parked at `curRow/curCol`; shown/hidden per the BDA cursor shape at
`0040:0060`. Idle → nothing sent. The top-right spinner is dropped (it corrupted
live VRAM and defeated idle-suppression). 80×43/50 modes diff-fall-back to
periodic full repaints (the 4 KB shadow diffs 80×25 only).

**Characters — CP437→UTF-8.** A resident 256-entry table maps each cell byte to
its UTF-8 glyph, so box-drawing/shading render on any UTF-8 terminal with zero
config; C0/`0x7F` remap to their PC glyphs (no raw control bytes), and UTF-8
never emits `0xFF` so no telnet escaping is needed. `/CP437RAW` opt-out emits the
raw byte (needs a CP437-font terminal + telnet `0xFF`-doubling).

**Input — server-side key map.** Raw terminal bytes → BIOS scancode/ascii →
`inject_key`. The Python client's keymap ports to C (ASCII→scancode, shifted
punctuation, CSI/SS3 escape sequences for arrows/F-keys). Telnet fixups:
CR / CR-LF / CR-NUL → one Enter; DEL/`0x08` → Backspace; Ctrl-A..Z. Lone-ESC vs
escape-sequence is disambiguated across ticks (buffer a pending ESC; inject a
bare ESC if no continuation arrives next tick).

**Telnet layer (network transport only).** On connect send `IAC WILL ECHO`,
`IAC WILL SGA`, `IAC DO SGA`, `IAC WILL BINARY`, `IAC DO BINARY` (character mode,
no double echo — the mirrored redraw *is* the echo — 8-bit clean). A loop-free
responder answers inbound negotiation once per option and skips `IAC SB…SE`
subnegotiations. Serial ANSI sends no IAC.

**Decomposition + tests** (rework the QEMU E2E harness with a shared ANSI→grid
decoder):
- **M5a — ANSI diff renderer (output).** Over serial: boot FreeDOS, decode the
  ANSI stream back to an 80×25 grid, assert the prompt appears; assert idle
  bandwidth ≪ a full repaint; CLS → a full repaint.
- **M5b — server key map (input).** Over serial: send raw key bytes, assert
  `echo BANANA` output appears (decoded from ANSI).
- **M5c — telnet + network.** Over the packet-driver TCP port: assert the opening
  IAC bytes, decode ANSI, assert screen + typing; a pexpect check over stock
  `telnet`/`nc`.
- Retire `client/dossh`; rewrite `docs/PROTOCOL.md` to document the telnet/ANSI
  behaviour; adapt e2e-m2/m3/m4.

**Decisions (resolved):** telnet-only (retire the binary protocol + client);
CP437→UTF-8 default + `/CP437RAW`; 4 KB shadow (diff 80×25, larger modes repaint).
