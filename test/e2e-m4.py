#!/usr/bin/env python3
"""
End-to-end test for M4: the packet-driver network transport.

Boots the DOSSH floppy with an emulated NE2000 NIC and a DOS packet driver;
AUTOEXEC runs `DOSSHD /NET`, which brings up its own ARP/IP/TCP stack and
listens. QEMU user-net forwards host tcp:127.0.0.1:PORT to the guest, so the
*same* client and wire protocol as the serial path reach it - the transport
swap is invisible above the byte stream.

The test proves the round trip over TCP-over-packet-driver: read SCREEN
frames, type `echo BANANA`, assert the echo output row appears.

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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5559"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "150"))  # driver + stack + 1st frame
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "45"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "30"))

MAGIC = b"DSSH"
HDR_LEN = 14
SCAN = {"e": 0x12, "c": 0x2E, "h": 0x23, "o": 0x18, " ": 0x39,
        "b": 0x30, "a": 0x1E, "n": 0x31, "\r": 0x1C}


def key_frame(ch):
    return MAGIC + bytes([2, SCAN[ch.lower()], ord(ch), 0])


def connect_when_ready(deadline):
    """The guest's TCP listener appears late and QEMU may accept then drop
    the host side until it is up; retry until a real byte stream flows."""
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        except OSError:
            time.sleep(0.5)
            continue
        s.settimeout(3)
        try:
            first = s.recv(65536)
        except socket.timeout:
            s.close()
            time.sleep(0.5)
            continue
        if not first:
            s.close()
            time.sleep(0.5)
            continue
        return s, bytearray(first)
    return None, bytearray()


def frames(sock, buf, deadline):
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
            raise ConnectionError("stream closed")
        buf += chunk


def expect(sock, buf, seconds, pred, label):
    last = None
    for rows in frames(sock, buf, time.time() + seconds):
        last = rows
        if pred(rows):
            print("e2e-m4: ok - %s" % label)
            return last
    print("e2e-m4: FAIL - %s; last screen:" % label, file=sys.stderr)
    for r in (last or []):
        sys.stderr.write("  |%s|\n" % r.rstrip())
    sys.exit(1)


def main():
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT="pkt"),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    sock = None
    try:
        deadline = time.time() + BOOT_TIMEOUT
        sock, buf = connect_when_ready(deadline)
        if sock is None:
            print("e2e-m4: FAIL - DOSSHD /NET never accepted a TCP stream",
                  file=sys.stderr)
            return 1

        expect(sock, buf, max(5, deadline - time.time()),
               lambda rows: True, "TCP stream up, SCREEN frame received")
        expect(sock, buf, PROMPT_TIMEOUT,
               lambda rows: any(":\\>" in r for r in rows),
               "shell prompt over the network")
        time.sleep(1.0)

        for ch in "echo BANANA\r":
            sock.sendall(key_frame(ch))
            time.sleep(0.06)
        print("e2e-m4: typed 'echo BANANA<CR>' over TCP")

        expect(sock, buf, ECHO_TIMEOUT,
               lambda rows: any(r.startswith("BANANA") for r in rows),
               "keys reached the shell over the packet driver")
        print("e2e-m4: PASS")
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
