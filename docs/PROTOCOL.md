# DOSSH wire protocol (telnet / ANSI)

DOSSH speaks a standard terminal protocol, so any client works — `telnet`,
`nc`, PuTTY, a serial terminal. There is no custom framing and no bespoke
client. The server sends the DOS text screen as an ANSI/VT100 byte stream and
accepts raw keystrokes back over the same connection.

## Server -> client: ANSI screen mirror

Every timer tick the resident server compares the live VGA text buffer
(`0xB8000`, or `0xB0000` in mono mode) against a shadow of the last frame and
emits ANSI only for the cells that changed:

- **Move** — `ESC [ <row> ; <col> H` (CUP, 1-based) before each run of changed
  cells, and at every row boundary.
- **Attribute** — `ESC [ 0 ; <fg> ; <bg> m` (SGR) whenever the VGA attribute
  changes. Foreground 0–15 maps to ANSI 30–37 / 90–97, background 0–7 to
  40–47, using the VGA→ANSI colour permutation `0,4,2,6,1,5,3,7`. The blink bit
  is dropped.
- **Character** — the CP437 cell byte re-encoded as **UTF-8**, so box-drawing
  and symbol glyphs render on a modern terminal. Control-range bytes
  `0x00–0x1F` and `0x7F` map to their PC display glyphs (e.g. `0x01`→☺), never
  raw control codes. `dosshd/cp437.c` holds the table.

Each frame hides the cursor while painting (`ESC[?25l`), then parks it at the
DOS cursor position and restores visibility (`ESC[?25h`) from the BIOS cursor
type at `0040:0060`.

A **full repaint** (`ESC[?25l ESC[2J ESC[H` + every cell) is sent on connect,
on a geometry change, when more than ~75% of the screen changed (CLS / scroll),
and — on the serial transport — every ~2 seconds so a terminal attaching
mid-stream resynchronises. Large repaints are paced across ticks. An idle,
unchanging screen produces no output between resyncs.

The shadow is sized for 80×25; larger text modes fall back to periodic full
repaints.

## Client -> server: raw keystrokes

The client sends the raw bytes a terminal produces; the server maps them to
BIOS scancodes and injects `(scancode << 8) | ascii` into the type-ahead ring
at `0040:001E`, so any program reading `INT 16h` receives them as if typed
locally (`dosshd/ansikey.c`).

- Printable ASCII → US-layout scancode + the byte as ASCII; shifted
  punctuation folds to its base key.
- `CR`, `CR LF`, `CR NUL` → one Enter (the paired `LF`/`NUL` is swallowed);
  `DEL`/`BS` → Backspace; `Tab` → Tab; `Ctrl-A..Z` → the control scancode.
- `ESC [ … ` (CSI) and `ESC O …` (SS3) → arrows, Home/End, PgUp/PgDn, Ins/Del
  and function keys, injected with ASCII 0 the way `INT 16h` reports extended
  keys.
- A lone `ESC` is distinguished from an escape sequence by a short timeout
  (a couple of timer ticks) before it is delivered as a bare ESC.

The ring holds only **15 keys**; the server drops keys when it is full, so
bulk input (pastes) should be paced.

## Transport

- **Serial:** COM1 at 115200 8N1, raw ANSI (no telnet). Under QEMU,
  `-serial tcp:...,server` bridges it to a host socket for `nc`/a terminal.
- **Network:** the server runs its own TCP stack (`dosshd/net.c`) over a DOS
  packet driver and listens on a static IP:port. On connect it negotiates
  **telnet** character mode — `IAC WILL ECHO`, `IAC WILL/DO SGA`,
  `IAC WILL/DO BINARY` — so `telnet`/PuTTY send a character at a time with no
  local echo (the mirrored redraw is the echo) and 8-bit clean. Inbound `IAC`
  sequences are stripped from the keystroke stream and answered once per
  option (`dosshd/telnet.c`).

## Planned (later milestones)

- Authentication (and optional encryption) over the network transport.
