#!/usr/bin/env python3
"""
End-to-end test for M2: remote keyboard injection.

Boots DOSSHD on a FreeDOS floppy under QEMU (COM1 bridged to TCP by
test/qemu-run.sh), then speaks the wire protocol directly: reads SCREEN
frames, types `echo BANANA` by sending KEY frames, and passes iff a screen
row *starts with* BANANA — the echo output, as opposed to the typed command
line, which sits after a prompt.

Exit 0 = pass, 1 = fail. Needs qemu-system-i386, mtools, and (first run)
network access to fetch the FreeDOS boot floppy.

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5556"))
BOOT_TIMEOUT = 120    # QEMU start -> first SCREEN frame
PROMPT_TIMEOUT = 45   # mirror up -> shell prompt visible
ECHO_TIMEOUT = 30     # keys sent -> BANANA on screen

MAGIC = b"DSSH"
HDR_LEN = 14

# BIOS scancode-set-1 make codes for the keys this test types
SCAN = {"e": 0x12, "c": 0x2E, "h": 0x23, "o": 0x18, " ": 0x39,
        "b": 0x30, "a": 0x1E, "n": 0x31, "\r": 0x1C}


def key_frame(ch):
    """Client->server KEY frame: DSSH, type=2, scancode, ascii, modifiers."""
    return MAGIC + bytes([2, SCAN[ch.lower()], ord(ch), 0])


def frames(sock, deadline):
    """Yield (rows, raw) per SCREEN frame until deadline; rows = list of str."""
    buf = bytearray()
    while time.time() < deadline:
        # resync on magic
        while len(buf) >= HDR_LEN and buf[:4] != MAGIC:
            del buf[0]
        if len(buf) >= HDR_LEN and buf[:4] == MAGIC:
            cols, rows_n = buf[7], buf[8]
            plen = buf[11] | (buf[12] << 8)
            if len(buf) >= HDR_LEN + plen:
                typ = buf[4]
                payload = bytes(buf[HDR_LEN:HDR_LEN + plen])
                del buf[:HDR_LEN + plen]
                if typ == 1 and plen == cols * rows_n * 2 and plen:
                    rows = ["".join(bytes([payload[(r * cols + c) * 2]])
                                    .decode("cp437")
                                    for c in range(cols))
                            for r in range(rows_n)]
                    yield rows
                continue
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return
        if not chunk:
            raise ConnectionError("serial stream closed")
        buf += chunk


def wait_for(sock, seconds, pred, label):
    """Consume frames until pred(rows) is true; return last rows seen."""
    last = None
    deadline = time.time() + seconds
    for rows in frames(sock, deadline):
        last = rows
        if pred(rows):
            print("e2e: %s after %.1fs" % (label, time.time() - deadline + seconds))
            return rows, True
    return last, False


def dump(rows, out=sys.stderr):
    if not rows:
        out.write("  (no frame received)\n")
        return
    for r in rows:
        out.write("  |%s|\n" % r.rstrip())


def main():
    env = dict(os.environ, PORT=str(PORT))
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    sock = None
    try:
        # the script may download the floppy first; retry the connect
        for _ in range(600):
            if qemu.poll() is not None:
                print("e2e: FAIL - qemu-run.sh exited early", file=sys.stderr)
                return 1
            try:
                sock = socket.create_connection(("127.0.0.1", PORT), timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            print("e2e: FAIL - serial port never opened", file=sys.stderr)
            return 1

        last, ok = wait_for(sock, BOOT_TIMEOUT, lambda rows: True, "mirror up")
        if not ok:
            print("e2e: FAIL - no SCREEN frame within %ds" % BOOT_TIMEOUT,
                  file=sys.stderr)
            return 1

        # a shell prompt means the injected keys have somewhere to go
        last, ok = wait_for(sock, PROMPT_TIMEOUT,
                            lambda rows: any(":\\>" in r for r in rows),
                            "shell prompt visible")
        if not ok:
            print("e2e: no shell prompt after %ds - typing anyway"
                  % PROMPT_TIMEOUT, file=sys.stderr)
        time.sleep(1.0)

        for ch in "echo BANANA\r":
            sock.sendall(key_frame(ch))
            time.sleep(0.06)
        print("e2e: typed 'echo BANANA<CR>'")

        last, ok = wait_for(sock, ECHO_TIMEOUT,
                            lambda rows: any(r.startswith("BANANA")
                                             for r in rows),
                            "echo output on screen")
        if ok:
            print("e2e: PASS - injected keys reached the shell")
            return 0
        print("e2e: FAIL - BANANA never appeared; last screen:",
              file=sys.stderr)
        dump(last)
        return 1
    finally:
        if sock:
            sock.close()
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        qemu.wait()


if __name__ == "__main__":
    sys.exit(main())
