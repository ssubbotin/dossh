# DOSSH wire protocol (M1)

M1 streams the text screen one way, DOS -> client, as length-framed messages
over a byte stream (serial in M1; TCP later). All integers are little-endian.

## Frame

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

## Planned (later milestones)

- `type` 2: cell-diff frames (only changed runs) for bandwidth/latency.
- client -> server `KEY` messages (scancode, ascii, modifiers) for input (M2).
- `HELLO`/`MODE`/`BELL`/`BYE` control messages.
- A UDP/TCP-over-packet-driver transport replacing serial as the primary path.
