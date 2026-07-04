# DOSSH wire protocol (M1/M2)

The screen streams DOS -> client as length-framed messages over a byte
stream (serial for now; TCP later); the client sends fixed-size KEY messages
back over the same stream. All integers are little-endian.

## SCREEN frame (server -> client)

```
offset  size  field
0       4     magic  = "DSSH"
4       1     type   = 1 (SCREEN)
5       2     seq    frame counter (wraps)
7       1     cols   columns (e.g. 80)
8       1     rows   rows (e.g. 25)
9       1     curRow cursor row (0-based)
10      1     curCol cursor column (0-based)
11      2     len    payload length in bytes (= cols*rows*2)
13      1     flags  = 0 (reserved)
14      len   cells  row-major array of (char, attr) pairs
```

Each cell is two bytes: a **CP437** character and a **VGA attribute** byte
(bits 0-3 foreground, 4-6 background, 7 blink/intensity) — the native format of
the PC text buffer at `0xB8000`, sent verbatim.

The client resynchronises by scanning for the `"DSSH"` magic, so a mid-stream
connect recovers on the next frame.

## KEY frame (client -> server, M2)

```
offset  size  field
0       4     magic     = "DSSH"
4       1     type      = 2 (KEY)
5       1     scancode  BIOS scancode-set-1 make code
6       1     ascii     character, or 0 for extended keys (arrows, F-keys)
7       1     modifiers reserved, send 0
```

The server injects `(scancode << 8) | ascii` into the BIOS type-ahead ring at
`0040:001E`, so any program reading the keyboard through `INT 16h` (DOS,
`COMMAND.COM`, full-screen tools) receives the key as if typed locally. The
ring holds only **15 keys**; clients must pace bulk input (e.g. pastes) to
give the foreground program time to drain it. The server drops keys when the
ring is full. It resynchronises on the `"DSSH"` magic byte-by-byte, so a
corrupt or truncated frame costs at most a few keys, not the session.

## Transport

The same length-framed byte stream runs over either transport, so one client
drives both:

- **Serial (M1–M3):** COM1 at 115200 8N1 (under QEMU, `-serial tcp:...,server`
  bridges it to a host socket).
- **Network (M4):** the server runs its own TCP stack (`dosshd/net.c`) over a
  DOS packet driver and listens on a static IP:port; the client connects to
  that TCP port. The wire framing above is byte-for-byte identical.

## Planned (later milestones)

- `type` 3+: cell-diff frames (only changed runs) for bandwidth/latency.
- `HELLO`/`MODE`/`BELL`/`BYE` control messages; `modifiers` semantics.
- Auth + optional encryption over the network transport.
