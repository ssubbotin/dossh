#!/usr/bin/env python3
"""
End-to-end test for M3: TSR / background operation (telnet/ANSI transport).

Boots the DOSSH floppy under QEMU. AUTOEXEC runs DOSSHD, which must go
resident and *return*, leaving the primary COMMAND.COM at its prompt. The
test then, entirely over the wire (raw terminal bytes in, ANSI out), checks
the things unique to a background TSR mirror:

  1. types `echo BANANA`   - keys reach the primary shell
  2. runs VIDTEST          - a program that writes straight to B800:0 (no BIOS)
                             still shows up in the mirror
  3. types `x` into VIDTEST - keys reach a program reading INT 16h
  4. quits it, `echo AFTERTEST` - the shell is alive again
  5. types `dosshd /u`     - uninstall: the mirror STOPS transmitting

Step 5 is the discriminator: a non-resident DOSSHD cannot uninstall, and the
~2 s ANSI resync cadence means a *live* mirror is never silent for long - so
sustained silence proves it truly unhooked.

Exit 0 = pass, 1 = fail.
MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansiterm import AnsiGrid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5558"))
BOOT_TIMEOUT = 120
STEP_TIMEOUT = 30
SILENCE_SECS = 5      # must exceed the ~2 s live-mirror resync cadence


def type_text(sock, text):
    for ch in text:
        sock.sendall(ch.encode())
        time.sleep(0.06)


def expect(sock, grid, seconds, pred, label):
    end = time.time() + seconds
    while time.time() < end:
        if pred(grid):
            print("e2e-m3: ok - %s" % label)
            return
        sock.settimeout(max(0.1, end - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            raise ConnectionError("serial stream closed")
        grid.feed(chunk)
    if pred(grid):
        print("e2e-m3: ok - %s" % label)
        return
    print("e2e-m3: FAIL - %s; last screen:" % label, file=sys.stderr)
    for r in grid.text().splitlines():
        if r.strip():
            sys.stderr.write("  |%s|\n" % r)
    sys.exit(1)


def rows(grid):
    return grid.text().splitlines()


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
                print("e2e-m3: FAIL - qemu-run.sh exited early", file=sys.stderr)
                return 1
            try:
                sock = socket.create_connection(("127.0.0.1", PORT), timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            print("e2e-m3: FAIL - serial port never opened", file=sys.stderr)
            return 1

        grid = AnsiGrid()
        expect(sock, grid, BOOT_TIMEOUT,
               lambda g: any(":\\>" in r for r in rows(g)),
               "primary shell prompt after DOSSHD went resident")
        time.sleep(1.0)

        type_text(sock, "echo BANANA\r")
        expect(sock, grid, STEP_TIMEOUT,
               lambda g: any(r.lstrip().startswith("BANANA") for r in rows(g)),
               "keys reach the primary shell")

        type_text(sock, "vidtest\r")
        expect(sock, grid, STEP_TIMEOUT,
               lambda g: any("VIDTEST:" in r for r in rows(g)),
               "direct-video program mirrored while TSR in background")

        # colour fidelity: VIDTEST paints its banner white-on-red (VGA 0x4F),
        # which the renderer must emit as SGR 97;41 - the ANSI decoder captures
        # it so we can assert the colour, not just the text.
        banner = None
        for y, line in enumerate(rows(grid)):
            x = line.find("VIDTEST:")
            if x >= 0:
                banner = grid.attr_at(y, x)
                break
        if banner == (97, 41, False):
            print("e2e-m3: ok - SGR colour correct (white-on-red banner)")
        else:
            print("e2e-m3: FAIL - VIDTEST banner colour = %r, want (97,41,False)"
                  % (banner,), file=sys.stderr)
            return 1

        type_text(sock, "x")
        expect(sock, grid, STEP_TIMEOUT,
               lambda g: any("KEY: x" in r for r in rows(g)),
               "keys reach a program reading INT 16h")

        type_text(sock, "q")
        time.sleep(0.5)
        type_text(sock, "echo AFTERTEST\r")
        expect(sock, grid, STEP_TIMEOUT,
               lambda g: any(r.lstrip().startswith("AFTERTEST") for r in rows(g)),
               "shell alive after the program exits")

        type_text(sock, "dosshd /u\r")
        end = time.time() + 6                     # drain the uninstall tail
        while time.time() < end:
            sock.settimeout(max(0.1, end - time.time()))
            try:
                if not sock.recv(65536):
                    break
            except socket.timeout:
                break
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
