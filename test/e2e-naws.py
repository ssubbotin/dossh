#!/usr/bin/env python3
"""
End-to-end test for telnet NAWS (RFC 1073) terminal-size handling.

Boots DOSSHD /NET and connects as a telnet client. Asserts that on connect the
server (a) negotiates NAWS - sends `IAC DO NAWS` (FF FD 1F) - and (b) asks the
terminal to size itself to 80x25 with an `ESC[8;25;80t` resize request. Then
sends NAWS subnegotiations (a size, then a different size to exercise the
resize->repaint path) and confirms the console stays healthy: the FreeDOS prompt
still decodes and typed keys still reach the shell. The mirror stays a fixed
80x25 - NAWS only drives the auto-resize and a clean repaint.

Exit 0 = pass, 1 = fail. Needs qemu-system-i386 and mtools.
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
PORT = int(os.environ.get("PORT", "5562"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "30"))

IAC, SB, SE, DO, NAWS = 0xFF, 0xFA, 0xF0, 0xFD, 0x1F


def naws(w, h):
    """A NAWS subnegotiation for a w x h window (no 0xFF in these sizes)."""
    return bytes([IAC, SB, NAWS, w >> 8, w & 0xFF, h >> 8, h & 0xFF, IAC, SE])


def connect_when_ready(deadline):
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


def read_until(sock, grid, pred, seconds, sink=None):
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
        if sink is not None:
            sink.append(chunk)
        grid.feed(chunk)
        if pred(grid):
            return True
    return pred(grid)


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    sock = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        sock, first = connect_when_ready(deadline)
        if sock is None:
            print("e2e-naws: FAIL - DOSSHD /NET never accepted a TCP stream",
                  file=sys.stderr)
            return 1

        # gather the opening bytes for a couple seconds (they may span chunks)
        grid = AnsiGrid()
        opening = [first]
        grid.feed(first)
        read_until(sock, grid, lambda g: False, 2.5, sink=opening)
        blob = b"".join(opening)

        if bytes([IAC, DO, NAWS]) not in blob:
            print("e2e-naws: FAIL - no IAC DO NAWS in opening bytes:",
                  repr(blob[:48]), file=sys.stderr)
            return 1
        print("e2e-naws: ok - server negotiates NAWS (IAC DO NAWS)")
        if b"\x1b[8;25;80t" not in blob:
            print("e2e-naws: FAIL - no ESC[8;25;80t resize request in opening bytes:",
                  repr(blob[:48]), file=sys.stderr)
            return 1
        print("e2e-naws: ok - server asks the terminal to size to 80x25")

        if not read_until(sock, grid, lambda g: g.contains(":\\>"),
                          max(5, deadline - time.time())):
            print("e2e-naws: FAIL - no shell prompt in the decoded ANSI",
                  file=sys.stderr)
            return 1
        print("e2e-naws: ok - FreeDOS prompt decodes")

        # report a size, then a different size (exercises capture + repaint path)
        sock.sendall(naws(80, 24)); time.sleep(0.5)
        sock.sendall(naws(80, 25)); time.sleep(0.8)
        print("e2e-naws: sent NAWS 80x24 then 80x25")

        for ch in "echo NAWSOK\r":
            sock.sendall(ch.encode()); time.sleep(0.06)
        if read_until(sock, grid,
                      lambda g: any(r.lstrip().startswith("NAWSOK")
                                    for r in g.text().splitlines()),
                      ECHO_TIMEOUT):
            print("e2e-naws: ok - console healthy after NAWS; keys still reach DOS")
            print("e2e-naws: PASS")
            return 0
        print("e2e-naws: FAIL - NAWSOK not echoed after NAWS; screen:", file=sys.stderr)
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
