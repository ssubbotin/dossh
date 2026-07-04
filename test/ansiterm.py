"""
ansiterm - a tiny ANSI/VT100 screen model for the DOSSH tests.

Feed it the byte stream a terminal would receive and it maintains an
rows x cols grid of characters, so a test can assert what a real terminal
would display. It understands exactly the subset DOSSHD emits: cursor
positioning (CUP), erase-screen, cursor show/hide, SGR (colour, ignored for
text content), and UTF-8 text. Telnet IAC sequences are stripped.

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""

IAC = 0xFF


class AnsiGrid:
    def __init__(self, cols=80, rows=25):
        self.cols = cols
        self.rows = rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.cx = 0
        self.cy = 0
        self.buf = bytearray()      # pending bytes (incomplete seq / UTF-8)

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid)

    def row(self, y):
        return "".join(self.grid[y])

    def contains(self, s):
        return any(s in "".join(r) for r in self.grid)

    def _put(self, ch):
        if self.cy < self.rows and self.cx < self.cols:
            self.grid[self.cy][self.cx] = ch
        self.cx += 1
        if self.cx >= self.cols:      # let CUP move us; don't autowrap grid state
            self.cx = self.cols - 1

    def _clear(self):
        for r in self.grid:
            for i in range(self.cols):
                r[i] = " "

    def feed(self, data):
        self.buf += data
        b = self.buf
        i = 0
        n = len(b)
        while i < n:
            c = b[i]
            if c == IAC:                      # telnet: IAC x / IAC SB..SE / IAC IAC
                if i + 1 >= n:
                    break
                nxt = b[i + 1]
                if nxt == IAC:
                    self._put("\xff"); i += 2; continue
                if nxt == 0xFA:               # SB ... IAC SE
                    j = b.find(bytes([IAC, 0xF0]), i + 2)
                    if j < 0:
                        break
                    i = j + 2; continue
                if nxt in (0xFB, 0xFC, 0xFD, 0xFE):   # WILL/WONT/DO/DONT opt
                    if i + 2 >= n:
                        break
                    i += 3; continue
                i += 2; continue              # IAC <other>
            if c == 0x1B:                     # ESC
                if i + 1 >= n:
                    break
                if b[i + 1] != ord("["):
                    i += 2; continue          # ESC <non-CSI>: ignore 2 bytes
                # CSI: ESC [ params... final(0x40-0x7e)
                j = i + 2
                while j < n and not (0x40 <= b[j] <= 0x7E):
                    j += 1
                if j >= n:
                    break                     # incomplete CSI; wait for more
                params = b[i + 2:j].decode("latin1")
                final = chr(b[j])
                self._csi(params, final)
                i = j + 1; continue
            if c == 0x0D:                     # CR
                self.cx = 0; i += 1; continue
            if c == 0x0A:                     # LF
                self.cy = min(self.cy + 1, self.rows - 1); i += 1; continue
            if c == 0x08:                     # BS
                self.cx = max(0, self.cx - 1); i += 1; continue
            if c < 0x20:                      # other C0: ignore
                i += 1; continue
            # UTF-8 char
            if c < 0x80:
                self._put(chr(c)); i += 1; continue
            need = 2 if c < 0xE0 else 3 if c < 0xF0 else 4
            if i + need > n:
                break                          # incomplete UTF-8; wait
            try:
                self._put(bytes(b[i:i + need]).decode("utf-8"))
            except UnicodeDecodeError:
                self._put("?")
            i += need
        del self.buf[:i]

    def _csi(self, params, final):
        if final == "H" or final == "f":       # CUP row;col (1-based)
            parts = params.split(";")
            r = int(parts[0]) if parts and parts[0] else 1
            col = int(parts[1]) if len(parts) > 1 and parts[1] else 1
            self.cy = max(0, min(self.rows - 1, r - 1))
            self.cx = max(0, min(self.cols - 1, col - 1))
        elif final == "J":                      # erase screen (2J = all)
            if params in ("2", "", "0", "3"):
                self._clear()
        elif final == "K":                      # erase line
            if self.cy < self.rows:
                for x in range(self.cx, self.cols):
                    self.grid[self.cy][x] = " "
        # SGR ('m'), cursor show/hide ('h'/'l'), etc.: no effect on text content
