#!/usr/bin/env python3
"""
End-to-end test for the reconnect-lockout fix (M5.1).

The failure it guards against: a client that drops without a clean TCP close
(VPN drop, laptop sleep - the flaky-link case this tool targets) leaves the
server pinned in ESTAB, and a *new* client's connection is then silently
dropped by the peer filter - the console is unreachable until a physical
reinstall.

We reproduce it by opening a second connection while the first is still up
(the first stands in for the dead-but-not-closed peer) and asserting the
second one is served: it must receive telnet IAC and the ANSI shell prompt.

Against the pre-fix build the second connection gets nothing (RED). With the
"a SYN in ESTAB means the old client is gone -> re-LISTEN and serve it" fix it
gets a fresh session (GREEN).

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
PORT = int(os.environ.get("PORT", "5561"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "45"))


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


def read_prompt(sock, grid, seed, seconds):
    if seed:
        grid.feed(seed)
    end = time.time() + seconds
    while time.time() < end and not grid.contains(":\\>"):
        sock.settimeout(max(0.2, end - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        grid.feed(chunk)
    return grid.contains(":\\>")


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    s1 = s2 = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        s1, first1 = connect_when_ready(deadline)
        if s1 is None:
            print("e2e-recon: FAIL - first connection never served", file=sys.stderr)
            return 1
        g1 = AnsiGrid()
        if not read_prompt(s1, g1, first1, SESSION_TIMEOUT):
            print("e2e-recon: FAIL - first session got no prompt", file=sys.stderr)
            return 1
        print("e2e-recon: ok - first client has a live session")

        # Leave s1 OPEN (the dead-but-not-closed peer) and connect again.
        time.sleep(1.0)
        s2, first2 = None, b""
        for _ in range(20):
            try:
                s2 = socket.create_connection(("127.0.0.1", PORT), timeout=2)
            except OSError:
                time.sleep(0.5); continue
            s2.settimeout(3)
            try:
                first2 = s2.recv(65536)
            except socket.timeout:
                first2 = b""
            break
        if s2 is None:
            print("e2e-recon: FAIL - could not open a second connection", file=sys.stderr)
            return 1

        if first2 and 0xFF in first2:
            print("e2e-recon: ok - second connection got telnet negotiation")
        g2 = AnsiGrid()
        if read_prompt(s2, g2, first2, SESSION_TIMEOUT):
            print("e2e-recon: ok - second client served while the first was still open")
            print("e2e-recon: PASS")
            return 0
        print("e2e-recon: FAIL - second connection locked out (no prompt); "
              "server stuck on the stale peer", file=sys.stderr)
        return 1
    finally:
        for s in (s1, s2):
            if s:
                s.close()
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        qemu.wait()


if __name__ == "__main__":
    sys.exit(main())
