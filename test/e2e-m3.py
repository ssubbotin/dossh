#!/usr/bin/env python3
"""
End-to-end test for M3: TSR / background operation.

Boots the DOSSH floppy under QEMU. AUTOEXEC runs DOSSHD, which must go
resident and *return*, leaving the primary COMMAND.COM at its prompt. The
test then, entirely over the wire:

  1. types `echo BANANA`        - keys reach the primary shell
  2. runs VIDTEST               - a separately launched program that writes
                                  straight to B800:0 shows up in the mirror
  3. types `x` into VIDTEST     - keys reach a program reading INT 16h
  4. quits it, `echo AFTERTEST` - the shell is alive again
  5. types `dosshd /u`          - uninstall: the mirror STOPS transmitting

Step 5 is the M3 discriminator: a non-resident DOSSHD cannot uninstall.

Exit 0 = pass, 1 = fail.
MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5558"))
BOOT_TIMEOUT = 120
STEP_TIMEOUT = 30
SILENCE_SECS = 4      # how long the line must stay dead after uninstall

MAGIC = b"DSSH"
HDR_LEN = 14

SCAN = {"a": 0x1E, "b": 0x30, "c": 0x2E, "d": 0x20, "e": 0x12, "f": 0x21,
        "g": 0x22, "h": 0x23, "i": 0x17, "j": 0x24, "k": 0x25, "l": 0x26,
        "m": 0x32, "n": 0x31, "o": 0x18, "p": 0x19, "q": 0x10, "r": 0x13,
        "s": 0x1F, "t": 0x14, "u": 0x16, "v": 0x2F, "w": 0x11, "x": 0x2D,
        "y": 0x15, "z": 0x2C, " ": 0x39, "/": 0x35, "\r": 0x1C}


def type_line(sock, text):
    for ch in text:
        sock.sendall(MAGIC + bytes([2, SCAN[ch.lower()], ord(ch), 0]))
        time.sleep(0.06)


def frames(sock, deadline):
    buf = bytearray()
    while time.time() < deadline:
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
                    yield ["".join(bytes([payload[(r * cols + c) * 2]])
                                   .decode("cp437") for c in range(cols))
                           for r in range(rows_n)]
                continue
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return
        if not chunk:
            raise ConnectionError("serial stream closed")
        buf += chunk


def expect(sock, seconds, pred, label):
    last = None
    for rows in frames(sock, time.time() + seconds):
        last = rows
        if pred(rows):
            print("e2e-m3: ok - %s" % label)
            return last
    print("e2e-m3: FAIL - %s; last screen:" % label, file=sys.stderr)
    for r in (last or []):
        sys.stderr.write("  |%s|\n" % r.rstrip())
    sys.exit(1)


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT)),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    sock = None
    try:
        for _ in range(600):
            if qemu.poll() is not None:
                print("e2e-m3: FAIL - qemu-run.sh exited early",
                      file=sys.stderr)
                return 1
            try:
                sock = socket.create_connection(("127.0.0.1", PORT),
                                                timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            print("e2e-m3: FAIL - serial port never opened", file=sys.stderr)
            return 1

        expect(sock, BOOT_TIMEOUT, lambda rows: True, "mirror up")
        expect(sock, STEP_TIMEOUT,
               lambda rows: any(":\\>" in r for r in rows),
               "primary shell prompt after DOSSHD went resident")
        time.sleep(1.0)

        type_line(sock, "echo BANANA\r")
        expect(sock, STEP_TIMEOUT,
               lambda rows: any(r.startswith("BANANA") for r in rows),
               "keys reach the primary shell")

        type_line(sock, "vidtest\r")
        expect(sock, STEP_TIMEOUT,
               lambda rows: any("VIDTEST:" in r for r in rows),
               "direct-video program mirrored while TSR in background")

        type_line(sock, "x")
        expect(sock, STEP_TIMEOUT,
               lambda rows: any("KEY: x" in r for r in rows),
               "keys reach a program reading INT 16h")

        type_line(sock, "q")
        time.sleep(0.5)
        type_line(sock, "echo AFTERTEST\r")
        expect(sock, STEP_TIMEOUT,
               lambda rows: any(r.startswith("AFTERTEST") for r in rows),
               "shell alive after the program exits")

        type_line(sock, "dosshd /u\r")
        for _ in frames(sock, time.time() + 6):   # drain the tail
            pass
        sock.settimeout(SILENCE_SECS)
        try:
            data = sock.recv(4096)
        except socket.timeout:
            data = b""
        if data:
            print("e2e-m3: FAIL - mirror still transmitting after /U",
                  file=sys.stderr)
            return 1
        print("e2e-m3: ok - uninstall stopped the mirror")
        print("e2e-m3: PASS")
        return 0
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
