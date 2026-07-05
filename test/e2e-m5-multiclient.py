#!/usr/bin/env python3
"""
End-to-end test for multi-client support: two telnet clients on one DOS box.

Boots DOSSHD /NET (PCnet + PCNTPK packet driver) and opens *two* independent TCP
connections to the guest listener - exactly as two people running `telnet` would
(QEMU user-net NATs them to the guest as two separate source ports). Asserts:

  * both clients negotiate telnet (IAC on connect) and decode the shell prompt,
    i.e. the second client to join gets a full repaint of the shared screen;
  * a keystroke typed by ONE client (`echo BANANA<CR>`) is injected into the DOS
    machine and its output appears on BOTH clients' screens (one broadcast mirror).

Because the screen stream is broadcast all-or-none (paced to the slowest client),
the test drains both sockets continuously via select - otherwise an unread client
would stall the shared stream for everyone.

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
PORT = int(os.environ.get("PORT", "5561"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "45"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "40"))


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


def pump(pairs, seconds, pred=None):
    """Read from every (sock, grid) via select for `seconds`, feeding each grid.
    Returns early (True) as soon as pred(grids) holds; keeps both peers drained
    so the all-or-none broadcast never blocks on an unread client."""
    grids = [g for _, g in pairs]
    end = time.time() + seconds
    if pred and pred(grids):
        return True
    while time.time() < end:
        socks = [s for s, _ in pairs]
        r, _, _ = select.select(socks, [], [], min(0.5, max(0.05, end - time.time())))
        for s in r:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                continue
            if chunk:
                for ps, pg in pairs:
                    if ps is s:
                        pg.feed(chunk)
        if pred and pred(grids):
            return True
    return pred(grids) if pred else False


def both_have_prompt(grids):
    return all(g.contains(":\\>") for g in grids)


def both_have_banana(grids):
    return all(any(r.lstrip().startswith("BANANA") for r in g.text().splitlines())
               for g in grids)


def dump(tag, grid):
    sys.stderr.write("  --- %s ---\n" % tag)
    for r in grid.text().splitlines():
        if r.strip():
            sys.stderr.write("  |%s|\n" % r)


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    sa = sb = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        sa, firsta = connect_when_ready(deadline)
        if sa is None:
            print("e2e-mc: FAIL - DOSSHD /NET never accepted client A", file=sys.stderr)
            return 1
        if 0xFF not in firsta:
            print("e2e-mc: WARN - no IAC in A's opening bytes:", repr(firsta[:24]),
                  file=sys.stderr)
        else:
            print("e2e-mc: ok - client A: telnet negotiation (IAC) on connect")

        ga = AnsiGrid(); ga.feed(firsta)
        if not pump([(sa, ga)], max(5, PROMPT_TIMEOUT), lambda gs: both_have_prompt(gs)):
            print("e2e-mc: FAIL - client A never showed the prompt", file=sys.stderr)
            dump("A", ga)
            return 1
        print("e2e-mc: ok - client A: decoded the FreeDOS prompt")

        # second client joins the live session
        sb, firstb = connect_when_ready(time.time() + 20)
        if sb is None:
            print("e2e-mc: FAIL - client B could not connect to the live server",
                  file=sys.stderr)
            return 1
        if 0xFF not in firstb:
            print("e2e-mc: WARN - no IAC in B's opening bytes:", repr(firstb[:24]),
                  file=sys.stderr)
        else:
            print("e2e-mc: ok - client B: telnet negotiation (IAC) on connect")
        gb = AnsiGrid(); gb.feed(firstb)

        # B's join forces a full repaint (broadcast); drain BOTH while it arrives
        pairs = [(sa, ga), (sb, gb)]
        if not pump(pairs, PROMPT_TIMEOUT, lambda gs: both_have_prompt(gs)):
            print("e2e-mc: FAIL - client B never got the shared screen repaint",
                  file=sys.stderr)
            dump("A", ga); dump("B", gb)
            return 1
        print("e2e-mc: ok - client B: got the full screen; both share one mirror")

        # one client types; the DOS box runs it; both screens must show the output
        pump(pairs, 1.0)                       # settle
        for ch in "echo BANANA\r":
            sa.sendall(ch.encode())
            pump(pairs, 0.08)                  # keep both drained between keys
        print("e2e-mc: client A typed 'echo BANANA<CR>'")

        if pump(pairs, ECHO_TIMEOUT, lambda gs: both_have_banana(gs)):
            print("e2e-mc: ok - BANANA shows on BOTH clients (broadcast mirror)")
            print("e2e-mc: PASS")
            return 0
        print("e2e-mc: FAIL - BANANA did not appear on both screens", file=sys.stderr)
        dump("A", ga); dump("B", gb)
        return 1
    finally:
        for s in (sa, sb):
            if s:
                s.close()
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        qemu.wait()


if __name__ == "__main__":
    sys.exit(main())
