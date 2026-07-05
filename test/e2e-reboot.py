#!/usr/bin/env python3
"""
End-to-end test for the in-band warm-reboot command.

Boots DOSSHD /NET under QEMU (with a monitor socket), connects over telnet,
sends the reboot sentinel (Ctrl-^ Ctrl-^ Ctrl-^ then Y = 0x1E 0x1E 0x1E 'Y'),
and confirms the box actually warm-boots by watching the guest video memory:
the SeaBIOS POST banner reappears at the top of the screen, which only happens
on a reboot.

Exit 0 = pass, 1 = fail. Needs qemu-system-i386, mtools, and a monitor socket.
MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import re
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5559"))
MON = os.environ.get("MON", "/tmp/dossh-reboot-mon.sock")
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))


def mon(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON)
    s.settimeout(3)
    time.sleep(0.2)
    try:
        s.recv(65536)
    except Exception:
        pass
    s.sendall((cmd + "\n").encode())
    out = b""
    end = time.time() + 2
    while time.time() < end:
        try:
            out += s.recv(65536)
        except socket.timeout:
            break
    s.close()
    return out.decode("latin1", "replace")


def row0():
    """The top screen row as text (char = even VRAM bytes at 0xB8000)."""
    txt = mon("xp/160xb 0xb8000")
    vals = [int(m, 16) for m in re.findall(r"0x([0-9a-fA-F]{2})", txt)]
    ch = [vals[i] for i in range(0, len(vals), 2)]
    return "".join(chr(c) if 32 <= c < 127 else " " for c in ch).strip()


def serving():
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
    except OSError:
        return False
    s.settimeout(3)
    try:
        ok = bool(s.recv(64))
    except socket.timeout:
        ok = False
    s.close()
    return ok


def main():
    if os.path.exists(MON):
        os.remove(MON)
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt", MON=MON),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    sock = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline and not serving():
            time.sleep(2)
        if not serving():
            print("e2e-reboot: FAIL - DOSSHD /NET never served", file=sys.stderr)
            return 1
        print("e2e-reboot: ok - box is up (top row: %r)" % row0()[:40])

        sock = socket.create_connection(("127.0.0.1", PORT), timeout=3)
        sock.settimeout(1.0)                             # drain opening frame + heal
        end = time.time() + 7
        while time.time() < end:
            try:
                if not sock.recv(65536):
                    break
            except socket.timeout:
                break
        for byte in (0x1E, 0x1E, 0x1E, ord("Y")):        # like a user typing it
            sock.sendall(bytes([byte]))
            time.sleep(0.4)
        print("e2e-reboot: sent sentinel (Ctrl-^ x3, Y)")

        # POST (SeaBIOS) only runs on a reboot - watch for it at the top row
        end = time.time() + 40
        seen_post = False
        while time.time() < end:
            r = row0()
            if "SeaBIOS" in r:
                seen_post = True
                print("e2e-reboot: ok - SeaBIOS POST seen (box is warm-booting)")
                break
            time.sleep(1.5)
        if not seen_post:
            print("e2e-reboot: FAIL - no POST seen; box did not reboot"
                  " (last top row: %r)" % row0()[:40], file=sys.stderr)
            return 1

        # ... and it comes back up
        end = time.time() + 90
        while time.time() < end and not serving():
            time.sleep(3)
        if serving():
            print("e2e-reboot: ok - DOSSHD /NET back after the reboot")
            print("e2e-reboot: PASS")
            return 0
        print("e2e-reboot: FAIL - box did not come back after reboot", file=sys.stderr)
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
