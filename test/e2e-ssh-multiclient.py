#!/usr/bin/env python3
"""
End-to-end test for multi-client native in-DOS SSH (the P3 milestone): TWO stock
`ssh` clients drive/watch ONE FreeDOS console at the same time, over SSH that
terminates on the DOS box.

Boots the SSH-enabled DOSSHDS.EXE (DOSSHD /SSH) on an emulated PCnet NIC under
QEMU (Pentium CPU) and opens *two* independent `ssh` sessions through QEMU
user-net hostfwd - exactly as two people running `ssh` would. Each client runs
its OWN SSH transport + userauth + session channel (its own keys), so the shared
screen is rendered once and framed+encrypted per client (docs/DESIGN-ssh.md
sec 4). Authentication is publickey: a throwaway ed25519 key is authorised via an
AUTHKEYS file and both clients present it (no password on the wire). Asserts:

  * both clients authenticate and open a shell channel;
  * both decode the FreeDOS prompt from their own encrypted channel (the second
    client to join gets a full repaint of the shared screen);
  * `echo AAA<CR>` typed by client 1 AND `echo BBB<CR>` typed by client 2 both
    reach DOS and appear on BOTH clients' decrypted screens (one merged keyboard,
    one broadcast mirror - now per-client-encrypted).

This is the SSH analogue of e2e-m5-multiclient (telnet). Exit 0 = pass, 1 = fail.
Needs qemu-system-i386, mtools, a real `ssh` client and `ssh-keygen` (self-skips
if any is missing), and - on first run - network access for the FreeDOS floppy
and the PCnet packet driver.

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansiterm import AnsiGrid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5572"))
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "240"))
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "60"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "45"))

KEYFILE = None  # set in main(): the private key both clients present

SSH_OPTS = [
    "-tt",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=6",
    "-o", "LogLevel=ERROR",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PubkeyAuthentication=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none",
]


class SshSession:
    """One `ssh` attempt with a background stdout reader feeding an AnsiGrid.
    Authenticates by publickey with our -i key (no password ever sent); writing
    to stdin reaches the remote channel, and ssh's screen output reaches our
    grid. A background reader keeps the socket drained so a slow client never
    stalls the shared broadcast for the other."""

    def __init__(self, tag):
        self.tag = tag
        cmd = ["ssh"] + SSH_OPTS + [
            "-i", KEYFILE, "-p", str(PORT), "user@127.0.0.1"]
        self.p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, preexec_fn=os.setsid)
        self.grid = AnsiGrid()
        self.raw = bytearray()
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            chunk = self.p.stdout.read(4096)
            if not chunk:
                break
            with self.lock:
                self.raw += chunk
                self.grid.feed(chunk)

    def alive(self):
        return self.p.poll() is None

    def got_output(self):
        with self.lock:
            return len(self.raw) > 0

    def contains(self, s):
        with self.lock:
            return self.grid.contains(s)

    def any_line_starts(self, s):
        with self.lock:
            return any(r.lstrip().startswith(s)
                       for r in self.grid.text().splitlines())

    def send(self, s):
        try:
            self.p.stdin.write(s.encode())
            self.p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def dump(self):
        with self.lock:
            sys.stderr.write("  --- client %s ---\n" % self.tag)
            for r in self.grid.text().splitlines():
                if r.strip():
                    sys.stderr.write("  |%s|\n" % r)
        try:
            err = self.p.stderr.read() if self.p.stderr else b""
            if err:
                sys.stderr.write("  %s ssh stderr: %s\n"
                                 % (self.tag, err.decode("latin1")[:400]))
        except Exception:
            pass

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(self.p.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            pass


def wait(pred, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.3)
    return pred()


def connect(tag, deadline):
    """Retry `ssh` until one attempt authenticates and the box starts sending its
    screen. The real-mode handshake (curve25519 + ed25519 + KDF) is sub-ms on
    real hardware but ~15-20 s under QEMU/TCG, so give one attempt room to finish
    rather than killing it mid-handshake."""
    while time.time() < deadline:
        s = SshSession(tag)
        if wait(lambda: s.got_output() or not s.alive(), 55):
            if s.got_output():
                return s
        s.close()
        time.sleep(2)
    return None


def main():
    global KEYFILE
    for tool in ("ssh", "ssh-keygen", "qemu-system-i386", "mcopy"):
        if not shutil.which(tool):
            print("SKIP: %s not found" % tool, file=sys.stderr)
            return 0
    if not os.path.exists(os.path.join(ROOT, "dosshd", "DOSSHDS.EXE")):
        print("SKIP: DOSSHDS.EXE not built (run dosshd/build.sh)", file=sys.stderr)
        return 0

    tmp = tempfile.mkdtemp(prefix="dossh-ssh-mc-")
    # A throwaway ed25519 key, authorised via AUTHKEYS. Both clients present it,
    # so publickey userauth admits both with NO password on the wire.
    KEYFILE = os.path.join(tmp, "id_dos")
    subprocess.check_call(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", KEYFILE,
         "-C", "dossh-e2e@multiclient"])
    authkeys = os.path.join(tmp, "AUTHKEYS")
    shutil.copyfile(KEYFILE + ".pub", authkeys)

    qenv = dict(os.environ, PORT=str(PORT), TRANSPORT="ssh", PW="",
                AUTHKEYS_SRC=authkeys)
    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=qenv, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    s1 = s2 = None
    try:
        # client 1 joins first and drives the box up to a prompt
        s1 = connect("1", time.time() + BOOT_TIMEOUT)
        if s1 is None:
            print("e2e-ssh-mc: FAIL - client 1 never authenticated", file=sys.stderr)
            return 1
        print("e2e-ssh-mc: ok - client 1 authenticated (publickey); channel up")
        if not wait(lambda: s1.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-mc: FAIL - client 1 saw no FreeDOS prompt", file=sys.stderr)
            s1.dump()
            return 1
        print("e2e-ssh-mc: ok - client 1 decoded the FreeDOS prompt")

        # client 2 joins the LIVE session; its join forces a shared repaint
        s2 = connect("2", time.time() + 120)
        if s2 is None:
            print("e2e-ssh-mc: FAIL - client 2 never authenticated", file=sys.stderr)
            s1.dump()
            return 1
        print("e2e-ssh-mc: ok - client 2 authenticated (publickey); 2 SSH clients live")
        if not wait(lambda: s2.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-mc: FAIL - client 2 got no shared-screen repaint",
                  file=sys.stderr)
            s1.dump(); s2.dump()
            return 1
        print("e2e-ssh-mc: ok - client 2 decoded the shared screen (its own keys)")

        time.sleep(1.0)  # settle

        # client 1 types: its keystrokes reach DOS; output must show on BOTH
        for ch in "echo AAA\r":
            s1.send(ch); time.sleep(0.06)
        print("e2e-ssh-mc: client 1 typed 'echo AAA<CR>'")
        if not wait(lambda: s1.any_line_starts("AAA") and s2.any_line_starts("AAA"),
                    ECHO_TIMEOUT):
            print("e2e-ssh-mc: FAIL - AAA did not appear on both clients",
                  file=sys.stderr)
            s1.dump(); s2.dump()
            return 1
        print("e2e-ssh-mc: ok - AAA (from client 1) shows on BOTH clients")

        # client 2 types: its keystrokes reach DOS too; output must show on BOTH
        for ch in "echo BBB\r":
            s2.send(ch); time.sleep(0.06)
        print("e2e-ssh-mc: client 2 typed 'echo BBB<CR>'")
        if not wait(lambda: s1.any_line_starts("BBB") and s2.any_line_starts("BBB"),
                    ECHO_TIMEOUT):
            print("e2e-ssh-mc: FAIL - BBB did not appear on both clients",
                  file=sys.stderr)
            s1.dump(); s2.dump()
            return 1
        print("e2e-ssh-mc: ok - BBB (from client 2) shows on BOTH clients")
        print("e2e-ssh-mc: PASS - two ssh clients drove one DOS box over SSH")
        return 0
    finally:
        for s in (s1, s2):
            if s:
                s.close()
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        qemu.wait()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
