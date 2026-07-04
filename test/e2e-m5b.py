#!/usr/bin/env python3
"""
End-to-end test for M5b: the server maps raw terminal bytes into DOS keystrokes.

Boots DOSSHD over serial, waits for the ANSI-rendered shell prompt, then sends
the *raw* bytes a terminal would send for `echo BANANA<Enter>` (no custom
protocol), and asserts the echo output row appears in the decoded ANSI screen -
i.e. a stock terminal can type into the DOS box.

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
PORT = int(os.environ.get("PORT", "5564"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "120"))


def read_until(sock, grid, pred, seconds):
    end = time.time() + seconds
    while time.time() < end:
        sock.settimeout(max(0.2, end - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            if pred(grid):
                return True
            continue
        if not chunk:
            break
        grid.feed(chunk)
        if pred(grid):
            return True
    return pred(grid)


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
                print("e2e-m5b: FAIL - qemu-run.sh exited early", file=sys.stderr)
                return 1
            try:
                sock = socket.create_connection(("127.0.0.1", PORT), timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            print("e2e-m5b: FAIL - serial port never opened", file=sys.stderr)
            return 1

        grid = AnsiGrid()
        if not read_until(sock, grid, lambda g: g.contains(":\\>"), BOOT_TIMEOUT):
            print("e2e-m5b: FAIL - no shell prompt", file=sys.stderr)
            return 1
        print("e2e-m5b: ok - shell prompt")
        time.sleep(1.0)

        for ch in "echo BANANA\r":          # raw terminal bytes, no protocol
            sock.sendall(ch.encode())
            time.sleep(0.06)
        print("e2e-m5b: sent raw 'echo BANANA<CR>'")

        if read_until(sock, grid, lambda g: g.contains("BANANA\n") or
                      any(r.lstrip().startswith("BANANA") for r in
                          grid.text().splitlines()), 30):
            print("e2e-m5b: ok - echo output shows on the ANSI screen")
            print("e2e-m5b: PASS")
            return 0
        print("e2e-m5b: FAIL - BANANA not echoed; screen:", file=sys.stderr)
        for r in grid.text().splitlines():
            if r.strip():
                sys.stderr.write("  |%s|\n" % r)
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
