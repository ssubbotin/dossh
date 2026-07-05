#!/usr/bin/env python3
"""
End-to-end test for the password auth gate (DOSSHD /NET ... /P:<pw>).

Boots DOSSHD /NET with a password and connects one telnet client. Asserts the
gate holds both the screen and the keyboard until the client authenticates:

  * on connect the client is prompted for a password and the DOS screen is
    withheld (no shell prompt decoded);
  * a WRONG password is rejected and still yields no console;
  * the RIGHT password grants the console (the FreeDOS prompt appears) and
    keystrokes then reach DOS (`echo BANANA<CR>` shows on screen).

Exit 0 = pass, 1 = fail. Needs qemu-system-i386, mtools, and (first run) network
access for the FreeDOS floppy and the packet driver.

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import select
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansiterm import AnsiGrid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5562"))
PW = os.environ.get("AUTH_PW", "s3cret")
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))
GRANT_TIMEOUT = int(os.environ.get("GRANT_TIMEOUT", "45"))


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


def pump(sock, grid, raw, seconds, pred=None):
    """Drain sock for up to `seconds`, feeding grid and appending to raw[0].
    Returns early (True) as soon as pred() holds."""
    end = time.time() + seconds
    if pred and pred():
        return True
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], min(0.5, max(0.05, end - time.time())))
        for s in r:
            try:
                chunk = s.recv(65536)
            except OSError:
                chunk = b""
            if chunk:
                raw[0] += chunk
                grid.feed(chunk)
        if pred and pred():
            return True
    return pred() if pred else False


def typed(sock, grid, raw, s):
    for ch in s:
        sock.sendall(ch.encode())
        pump(sock, grid, raw, 0.12)


def has_prompt(grid):
    return grid.contains(":\\>")


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt", PW=PW),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    s = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        s, first = connect_when_ready(deadline)
        if s is None:
            print("e2e-auth: FAIL - DOSSHD /NET never accepted a client", file=sys.stderr)
            return 1
        grid = AnsiGrid(); grid.feed(first)
        raw = [first]
        if 0xFF in first:
            print("e2e-auth: ok - telnet negotiation (IAC) on connect")

        # 1) prompted for a password, and the console is withheld
        pump(s, grid, raw, 8, lambda: b"assword" in raw[0])
        if b"assword" not in raw[0]:
            print("e2e-auth: FAIL - no password prompt", file=sys.stderr)
            return 1
        if has_prompt(grid):
            print("e2e-auth: FAIL - DOS console shown BEFORE auth", file=sys.stderr)
            return 1
        print("e2e-auth: ok - prompted for a password; console withheld")

        # 2) a wrong password is rejected and grants nothing
        typed(s, grid, raw, "wr0ngpw\r")
        pump(s, grid, raw, 6, lambda: b"rong password" in raw[0] or b"enied" in raw[0])
        if has_prompt(grid):
            print("e2e-auth: FAIL - console granted after a WRONG password", file=sys.stderr)
            return 1
        print("e2e-auth: ok - wrong password rejected; still no console")

        # 3) the right password grants the console
        typed(s, grid, raw, PW + "\r")
        if not pump(s, grid, raw, GRANT_TIMEOUT, lambda: has_prompt(grid)):
            print("e2e-auth: FAIL - correct password did not grant the console",
                  file=sys.stderr)
            for r in grid.text().splitlines():
                if r.strip():
                    sys.stderr.write("  |%s|\n" % r)
            return 1
        print("e2e-auth: ok - correct password granted the DOS console")

        # 4) keystrokes reach DOS now that the gate is open
        typed(s, grid, raw, "echo BANANA\r")
        if pump(s, grid, raw, 40,
                lambda: any(r.lstrip().startswith("BANANA")
                            for r in grid.text().splitlines())):
            print("e2e-auth: ok - keystrokes reach DOS after auth (BANANA)")
            print("e2e-auth: PASS")
            return 0
        print("e2e-auth: FAIL - keystrokes did not reach DOS after auth", file=sys.stderr)
        return 1
    finally:
        if s:
            s.close()
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        qemu.wait()


if __name__ == "__main__":
    sys.exit(main())
