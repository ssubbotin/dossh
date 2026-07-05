#!/usr/bin/env python3
"""
End-to-end test for the opt-in Ctrl-D disconnect (the /EOF install flag) over the
native in-DOS SSH server (DOSSHDS.EXE).

DOSSH is a transparent KVM: by default every key - including Ctrl-D (0x04) -
reaches DOS. With /EOF on the command line the byte 0x04 from a connected client
instead disconnects THAT ONE client's SSH session: the server closes its channel
(CHANNEL_EOF + CHANNEL_CLOSE + exit-status) and drops its slot, without touching
the box or any other client. This test proves both directions against a real
OpenSSH client driving a FreeDOS box under QEMU:

  Phase 1 (/EOF ON):
    * a real `ssh` authenticates and the FreeDOS prompt shows on the channel;
    * sending Ctrl-D (0x04) makes that ssh session EXIT (the channel closes);
    * the box stays up - a SECOND fresh ssh session still connects and prompts.

  Phase 2 (/EOF OFF, the default):
    * a real `ssh` authenticates and prompts;
    * sending Ctrl-D (0x04) does NOT disconnect - the session stays alive and
      `echo BANANA<CR>` still reaches DOS and echoes, so 0x04 passed through to
      DOS as an ordinary keystroke.

The companion of e2e-ssh-dos.py, reusing the same PCnet + QEMU user-net + real
`ssh` path (publickey by default; SSH_AUTH=password for the sshpass path). Exit
0 = pass, 1 = fail. Needs qemu-system-i386, mtools, a real `ssh` client,
`sshpass` and `ssh-keygen` (self-skips if any is missing).

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
PORT = int(os.environ.get("PORT", "5573"))
PW = os.environ.get("SSH_PW", "dosbanana")
# "ssh": native SSH over the PCnet packet driver + QEMU user-net (the primary
# path). "sshser": the same SSH server over COM1, bridged to a host TCP port.
SSH_TRANSPORT = os.environ.get("SSH_TRANSPORT", "ssh")
# "publickey" (default): the box loads an AUTHKEYS file and `ssh -i <key>`
# authenticates with NO password on the wire. "password": the sshpass path.
SSH_AUTH = os.environ.get("SSH_AUTH", "publickey")
BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "240"))
PROMPT_TIMEOUT = int(os.environ.get("PROMPT_TIMEOUT", "60"))
DISCONNECT_TIMEOUT = int(os.environ.get("DISCONNECT_TIMEOUT", "30"))
# how long we insist the /EOF-off session stays connected after Ctrl-D
HOLD_TIMEOUT = int(os.environ.get("HOLD_TIMEOUT", "12"))
ECHO_TIMEOUT = int(os.environ.get("ECHO_TIMEOUT", "45"))

KEYFILE = None  # set in main() for publickey mode

SSH_OPTS = [
    "-tt",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=6",
    "-o", "LogLevel=ERROR",
]
PW_OPTS = ["-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
PK_OPTS = ["-o", "PreferredAuthentications=publickey", "-o", "PubkeyAuthentication=yes",
           "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"]


class SshSession:
    """One `ssh` attempt with a background stdout reader feeding an AnsiGrid."""

    def __init__(self):
        if SSH_AUTH == "publickey":
            cmd = ["ssh"] + SSH_OPTS + PK_OPTS + [
                "-i", KEYFILE, "-p", str(PORT), "user@127.0.0.1"]
        else:
            cmd = ["sshpass", "-p", PW, "ssh"] + SSH_OPTS + PW_OPTS + [
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
            if isinstance(s, str):
                s = s.encode()
            self.p.stdin.write(s)
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


def stays_alive(s, seconds):
    """True iff s never exits during the window (the opposite of wait-for-death)."""
    end = time.time() + seconds
    while time.time() < end:
        if not s.alive():
            return False
        time.sleep(0.3)
    return s.alive()


def connect(deadline):
    """Retry `ssh` until one attempt authenticates and the screen starts flowing."""
    while time.time() < deadline:
        s = SshSession()
        if wait(lambda: s.got_output() or not s.alive(), 50):
            if s.got_output():
                return s
        s.close()
        time.sleep(2)
    return None


def boot_qemu(eof, tmp, authkeys):
    qenv = dict(os.environ, PORT=str(PORT), TRANSPORT=SSH_TRANSPORT, PW=PW)
    if eof:
        qenv["EOF"] = "1"
    if SSH_AUTH == "publickey":
        qenv["AUTHKEYS_SRC"] = authkeys
    return subprocess.Popen(
        ["bash", os.path.join(ROOT, "test", "qemu-run.sh")],
        env=qenv, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)


def kill_qemu(qemu):
    try:
        os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        qemu.wait(timeout=10)
    except Exception:
        pass


def phase_eof_on(tmp, authkeys):
    """/EOF ON: Ctrl-D disconnects that session; the box stays up for others."""
    print("== phase 1: /EOF ON - Ctrl-D disconnects the session ==")
    qemu = boot_qemu(True, tmp, authkeys)
    s1 = s2 = None
    try:
        s1 = connect(time.time() + BOOT_TIMEOUT)
        if s1 is None:
            print("e2e-ssh-ctrld: FAIL - no ssh session ever authenticated (/EOF on)",
                  file=sys.stderr)
            return 1
        print("e2e-ssh-ctrld: ok - real ssh authenticated (%s), channel up" % SSH_AUTH)
        if not wait(lambda: s1.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - no FreeDOS prompt before Ctrl-D",
                  file=sys.stderr)
            s1.dump()
            return 1
        print("e2e-ssh-ctrld: ok - FreeDOS prompt on the decrypted channel")
        time.sleep(1.0)

        s1.send(b"\x04")   # Ctrl-D
        print("e2e-ssh-ctrld: sent Ctrl-D (0x04) over the SSH channel")
        if not wait(lambda: not s1.alive(), DISCONNECT_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - ssh session did NOT close on Ctrl-D "
                  "(with /EOF it must)", file=sys.stderr)
            s1.dump()
            return 1
        print("e2e-ssh-ctrld: ok - the ssh session closed on Ctrl-D "
              "(exit=%s)" % s1.p.poll())

        # the box must still be alive: a fresh session connects and prompts.
        s2 = connect(time.time() + 90)
        if s2 is None:
            print("e2e-ssh-ctrld: FAIL - box unreachable after the disconnect "
                  "(did Ctrl-D take down more than one session?)", file=sys.stderr)
            return 1
        if not wait(lambda: s2.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - second session got no prompt "
                  "(box wedged?)", file=sys.stderr)
            s2.dump()
            return 1
        print("e2e-ssh-ctrld: ok - box still up; a second ssh session prompts")
        return 0
    finally:
        for s in (s1, s2):
            if s:
                s.close()
        kill_qemu(qemu)


def phase_eof_off(tmp, authkeys):
    """/EOF OFF (default): Ctrl-D passes through to DOS; the session stays up."""
    print("== phase 2: /EOF OFF - Ctrl-D reaches DOS, session stays up ==")
    qemu = boot_qemu(False, tmp, authkeys)
    s = None
    try:
        s = connect(time.time() + BOOT_TIMEOUT)
        if s is None:
            print("e2e-ssh-ctrld: FAIL - no ssh session ever authenticated (/EOF off)",
                  file=sys.stderr)
            return 1
        if not wait(lambda: s.contains(":\\>"), PROMPT_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - no FreeDOS prompt before Ctrl-D (/EOF off)",
                  file=sys.stderr)
            s.dump()
            return 1
        print("e2e-ssh-ctrld: ok - FreeDOS prompt on the decrypted channel")
        time.sleep(1.0)

        s.send(b"\x04")   # Ctrl-D
        print("e2e-ssh-ctrld: sent Ctrl-D (0x04); session must NOT close")
        if not stays_alive(s, HOLD_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - Ctrl-D disconnected the session with NO "
                  "/EOF (default must pass 0x04 through to DOS)", file=sys.stderr)
            s.dump()
            return 1
        print("e2e-ssh-ctrld: ok - session stayed connected through Ctrl-D")

        # and the channel is still a live pipe: a keystroke still reaches DOS.
        for ch in "echo BANANA\r":
            s.send(ch)
            time.sleep(0.06)
        if not wait(lambda: s.any_line_starts("BANANA"), ECHO_TIMEOUT):
            print("e2e-ssh-ctrld: FAIL - after Ctrl-D the channel no longer drives "
                  "DOS (echo not seen)", file=sys.stderr)
            s.dump()
            return 1
        print("e2e-ssh-ctrld: ok - keystrokes still reach DOS after Ctrl-D "
              "(0x04 passed through)")
        return 0
    finally:
        if s:
            s.close()
        kill_qemu(qemu)


def main():
    global KEYFILE
    if not shutil.which("ssh"):
        print("SKIP: no ssh client binary found", file=sys.stderr)
        return 0
    if not shutil.which("sshpass"):
        print("SKIP: sshpass not found", file=sys.stderr)
        return 0
    if SSH_AUTH == "publickey" and not shutil.which("ssh-keygen"):
        print("SKIP: ssh-keygen not found (needed for publickey mode)", file=sys.stderr)
        return 0
    if not os.path.exists(os.path.join(ROOT, "dosshd", "DOSSHDS.EXE")):
        print("SKIP: DOSSHDS.EXE not built (run dosshd/build.sh)", file=sys.stderr)
        return 0

    tmp = tempfile.mkdtemp(prefix="dossh-ssh-ctrld-")
    authkeys = None
    try:
        if SSH_AUTH == "publickey":
            KEYFILE = os.path.join(tmp, "id_dos")
            subprocess.check_call(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", KEYFILE,
                 "-C", "dossh-e2e@ctrld"])
            authkeys = os.path.join(tmp, "AUTHKEYS")
            shutil.copyfile(KEYFILE + ".pub", authkeys)

        rc = phase_eof_on(tmp, authkeys)
        if rc != 0:
            return rc
        rc = phase_eof_off(tmp, authkeys)
        if rc != 0:
            return rc
        print("e2e-ssh-ctrld: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
