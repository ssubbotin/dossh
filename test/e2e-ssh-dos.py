#!/usr/bin/env python3
"""
End-to-end test for native in-DOS SSH (the P1 milestone): a stock `ssh` client
drives a real FreeDOS console whose SSH crypto runs on the DOS box itself.

Boots the SSH-enabled DOSSHDS.EXE (DOSSHD /SSH ... /P:<pw>) on an emulated PCnet
NIC under QEMU with a Pentium CPU (the crypto needs a 386, rng's RDTSC a 586),
and connects with a real OpenSSH client through QEMU user-net hostfwd - the whole
SSH transport + password userauth + session channel terminates on DOS, in the
timer tick. Asserts:

  * a real `ssh` authenticates with the password and opens a shell channel;
  * the DOS screen arrives over the encrypted channel and decodes to the FreeDOS
    prompt;
  * typing `echo BANANA<CR>` reaches DOS and its output shows on the screen.

This is the SSH analogue of e2e-m5c. Exit 0 = pass, 1 = fail. Needs
qemu-system-i386, mtools, a real `ssh` client and `sshpass` (self-skips if any
is missing), and - on first run - network access for the FreeDOS floppy and the
PCnet packet driver.

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ansiterm import AnsiGrid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("PORT", "5570"))
PW = os.environ.get("SSH_PW", "dosbanana")
# "ssh": native SSH over the PCnet packet driver + QEMU user-net (the primary
# path). "sshser": the same SSH server over COM1, bridged to a host TCP port -
# functionally identical to a stock ssh client, and the only path usable where
# QEMU's user-mode networking is unavailable (e.g. some sandboxes).
SSH_TRANSPORT = os.environ.get("SSH_TRANSPORT", "ssh")
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "240"))
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "60"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "45"))

SSH_OPTS = [
    "-tt",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=6",
    "-o", "LogLevel=ERROR",
]


class SshSession:
    """One `sshpass ... ssh` attempt with a background stdout reader that feeds
    an AnsiGrid. sshpass wires ssh's stdin/stdout through a pty it relays, so
    writing to our stdin reaches the remote channel and ssh's screen output
    reaches our grid."""

    def __init__(self):
        cmd = ["sshpass", "-p", PW, "ssh"] + SSH_OPTS + [
            "-p", str(PORT), "user@127.0.0.1"]
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
            for r in self.grid.text().splitlines():
                if r.strip():
                    sys.stderr.write("  |%s|\n" % r)
        try:
            err = self.p.stderr.read() if self.p.stderr else b""
            if err:
                sys.stderr.write("  ssh stderr: %s\n" % err.decode("latin1")[:400])
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


def connect(deadline):
    """Retry `ssh` until one attempt authenticates and the box starts sending
    its screen (the guest listener comes up late during boot)."""
    while time.time() < deadline:
        s = SshSession()
        # success = the channel is up and the DOS screen is flowing; failure =
        # the client exits first (connection refused/reset: guest not up yet).
        # the real-mode SSH handshake (curve25519 + ed25519 + key derivation) is
        # sub-ms on real hardware but takes ~15-20s under QEMU/TCG emulation, so
        # give one attempt room to finish rather than killing it mid-handshake
        # (which would wedge the single-client server for the retries).
        if wait(lambda: s.got_output() or not s.alive(), 50):
            if s.got_output():
                return s
        s.close()
        time.sleep(2)
    return None


def main():
    if not shutil.which("ssh"):
        print("SKIP: no ssh client binary found", file=sys.stderr)
        return 0
    if not shutil.which("sshpass"):
        print("SKIP: sshpass not found", file=sys.stderr)
        return 0
    if not os.path.exists(os.path.join(ROOT, "dosshd", "DOSSHDS.EXE")):
        print("SKIP: DOSSHDS.EXE not built (run dosshd/build.sh)", file=sys.stderr)
        return 0

    qemu = subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=dict(os.environ, PORT=str(PORT), TRANSPORT=SSH_TRANSPORT, PW=PW),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    s = None
    try:
        s = connect(time.time() + BOOT_TIMEOUT)
        if s is None:
            print("e2e-ssh-dos: FAIL - no ssh session ever authenticated",
                  file=sys.stderr)
            return 1
        print("e2e-ssh-dos: ok - real ssh authenticated (password) and the "
              "channel is up")

        if not wait(lambda: s.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-dos: FAIL - no FreeDOS prompt in the decrypted ANSI",
                  file=sys.stderr)
            s.dump()
            return 1
        print("e2e-ssh-dos: ok - decrypted SSH channel shows the FreeDOS prompt")
        time.sleep(1.0)

        for ch in "echo BANANA\r":
            s.send(ch)
            time.sleep(0.06)
        print("e2e-ssh-dos: typed 'echo BANANA<CR>' over the SSH channel")

        if wait(lambda: s.any_line_starts("BANANA"), ECHO_TIMEOUT):
            print("e2e-ssh-dos: ok - keystrokes reached DOS; echo shows on screen")
            print("e2e-ssh-dos: PASS")
            return 0
        print("e2e-ssh-dos: FAIL - BANANA not echoed; screen:", file=sys.stderr)
        s.dump()
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
