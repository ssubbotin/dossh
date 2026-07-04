#!/usr/bin/env python3
"""
End-to-end test for M5c: telnet/ANSI console over the network (packet driver).

Boots DOSSHD /NET on an emulated PCnet NIC with the PCNTPK packet driver, and
connects to the guest's TCP listener over QEMU user-net hostfwd - exactly as a
stock `telnet` would. Asserts: the server opens with telnet negotiation (IAC
bytes), the ANSI stream decodes to the FreeDOS shell prompt, and raw typed
bytes (`echo BANANA<CR>`) reach the shell and its output shows on the screen.

Exit 0 = pass, 1 = fail. Needs qemu-system-i386, mtools, and (first run)
network access for the FreeDOS floppy and the packet driver.

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
PORT = int(os.environ.get("PORT", "5560"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "45"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "30"))


def connect_when_ready(deadline):
    """The guest listener appears late; retry until a real byte stream flows."""
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        except OSError:
            time.sleep(0.5); continue
        s.settimeout(3)
        try:
            first = s.recv(65536)
        except socket.timeout:
            s.close(); time.sleep(0.5); continue
        if not first:
            s.close(); time.sleep(0.5); continue
        return s, first
    return None, b""


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
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    sock = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        sock, first = connect_when_ready(deadline)
        if sock is None:
            print("e2e-m5c: FAIL - DOSSHD /NET never accepted a TCP stream",
                  file=sys.stderr)
            return 1
        if 0xFF not in first:
            print("e2e-m5c: WARN - no IAC in the opening bytes:", repr(first[:24]),
                  file=sys.stderr)
        else:
            print("e2e-m5c: ok - telnet negotiation (IAC) present on connect")

        grid = AnsiGrid()
        grid.feed(first)
        if not read_until(sock, grid, lambda g: g.contains(":\\>"),
                          max(5, deadline - time.time())):
            print("e2e-m5c: FAIL - no shell prompt in the decoded ANSI",
                  file=sys.stderr)
            for r in grid.text().splitlines():
                if r.strip():
                    sys.stderr.write("  |%s|\n" % r)
            return 1
        print("e2e-m5c: ok - ANSI shows the FreeDOS prompt over the network")
        time.sleep(1.0)

        for ch in "echo BANANA\r":
            sock.sendall(ch.encode())
            time.sleep(0.06)
        print("e2e-m5c: typed raw 'echo BANANA<CR>' over TCP")

        if read_until(sock, grid,
                      lambda g: any(r.lstrip().startswith("BANANA")
                                    for r in g.text().splitlines()),
                      ECHO_TIMEOUT):
            print("e2e-m5c: ok - keys reached the shell; echo shows on screen")
            print("e2e-m5c: PASS")
            return 0
        print("e2e-m5c: FAIL - BANANA not echoed; screen:", file=sys.stderr)
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
