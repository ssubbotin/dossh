#!/usr/bin/env python3
"""
End-to-end test for M5a: the server renders the DOS text screen as ANSI.

Boots DOSSHD over serial under QEMU, reads the byte stream a terminal would
receive, decodes it as ANSI into an 80x25 grid (test/ansiterm.py), and asserts
the FreeDOS boot text + shell prompt appear - i.e. a stock terminal would show
the live screen with no custom client. Also checks that once the screen is
static the server goes near-silent (diffing), rather than re-sending the whole
screen every tick.

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
PORT = int(os.environ.get("PORT", "5563"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "120"))


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
                print("e2e-m5a: FAIL - qemu-run.sh exited early", file=sys.stderr)
                return 1
            try:
                sock = socket.create_connection(("127.0.0.1", PORT), timeout=1)
                break
            except OSError:
                time.sleep(0.5)
        else:
            print("e2e-m5a: FAIL - serial port never opened", file=sys.stderr)
            return 1

        grid = AnsiGrid()
        deadline = time.time() + BOOT_TIMEOUT
        got_prompt = False
        while time.time() < deadline:
            sock.settimeout(max(0.2, deadline - time.time()))
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            grid.feed(chunk)
            if grid.contains(":\\>"):        # FreeDOS shell prompt (A:\>)
                got_prompt = True
                break

        if not got_prompt:
            print("e2e-m5a: FAIL - no shell prompt in the decoded ANSI screen;"
                  " last screen:", file=sys.stderr)
            for r in grid.text().splitlines():
                if r.strip():
                    sys.stderr.write("  |%s|\n" % r)
            return 1
        print("e2e-m5a: ok - decoded ANSI shows the FreeDOS prompt")

        # idle-bandwidth: once static, a diffing server sends far less than a
        # full 80x25 repaint (~2000+ bytes) per second.
        time.sleep(1.5)
        sock.settimeout(3.0)
        idle = 0
        try:
            end = time.time() + 3.0
            while time.time() < end:
                sock.settimeout(max(0.1, end - time.time()))
                idle += len(sock.recv(65536))
        except socket.timeout:
            pass
        print("e2e-m5a: idle bytes over ~3s: %d" % idle)
        if idle > 6000:
            print("e2e-m5a: FAIL - not diffing (idle stream too large)",
                  file=sys.stderr)
            return 1
        print("e2e-m5a: ok - idle stream is small (diffing works)")
        print("e2e-m5a: PASS")
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
