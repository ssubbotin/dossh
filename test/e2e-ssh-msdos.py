#!/usr/bin/env python3
"""
Local e2e: the native in-DOS SSH server on **MS-DOS 6.22** (not FreeDOS).

The automated suite boots FreeDOS (freely redistributable, fetched in CI). This
test proves the SAME DOSSHDS.EXE also runs on genuine MS-DOS 6.22, driven by a
real `ssh` client: it copies PCNTPK.COM + DOSSHDS.EXE + a small AUTOEXEC onto a
COPY of a bootable MS-DOS 6.22 floppy you supply, boots it under QEMU (pcnet NIC,
Pentium2 CPU — the -3 crypto needs a 386, rng's RDTSC a 586), and asserts a stock
`ssh` authenticates, decodes the DOS screen, and `echo BANANA` reaches DOS.

MS-DOS 6.22 is not redistributable, so this is a LOCAL/manual test — point it at
your own image and it runs; otherwise it self-skips:

    MSDOS_IMG=/path/to/msdos622-boot.img python3 test/e2e-ssh-msdos.py

Exit 0 = pass (or skip), 1 = fail. MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import os, re, signal, socket, subprocess, sys, tempfile, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "test"))
from ansiterm import AnsiGrid

MSDOS_IMG = os.environ.get("MSDOS_IMG", "")
PORT = int(os.environ.get("PORT", "2222"))
PW = os.environ.get("SSH_PW", "dossh")


def mon_factory(sock):
    def mon(cmd):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
        s.settimeout(3); time.sleep(0.15)
        try: s.recv(65536)
        except Exception: pass
        s.sendall((cmd + "\n").encode()); out = b""; e = time.time() + 1.5
        while time.time() < e:
            try: out += s.recv(65536)
            except socket.timeout: break
        s.close(); return out.decode("latin1", "replace")
    return mon


def screen(mon):
    txt = mon("xp/4000xb 0xb8000")
    vals = [int(m, 16) for m in re.findall(r"0x([0-9a-fA-F]{2})", txt)]
    ch = [vals[i] for i in range(0, len(vals), 2)]
    return "\n".join("".join(chr(c) if 32 <= c < 127 else " " for c in ch[r * 80:(r + 1) * 80]).rstrip()
                     for r in range(25))


def main():
    for tool in ("qemu-system-i386", "mcopy", "ssh", "sshpass"):
        if not _which(tool):
            print("SKIP: %s not found" % tool, file=sys.stderr); return 0
    if not MSDOS_IMG or not os.path.exists(MSDOS_IMG):
        print("SKIP: set MSDOS_IMG=/path/to/a/bootable/msdos622.img to run this "
              "(MS-DOS 6.22 is not redistributable).", file=sys.stderr); return 0
    dosshds = os.path.join(ROOT, "dosshd", "DOSSHDS.EXE")
    pcntpk = os.path.join(ROOT, "test", "work", "PCNTPK.COM")
    if not (os.path.exists(dosshds) and os.path.exists(pcntpk)):
        print("SKIP: build DOSSHDS.EXE and fetch PCNTPK.COM first (dosshd/build.sh; "
              "test/qemu-run.sh TRANSPORT=pkt caches PCNTPK).", file=sys.stderr); return 0

    tmp = tempfile.mkdtemp(prefix="dossh-msdos-")
    img = os.path.join(tmp, "msdos-ssh.img")
    subprocess.run(["cp", "-f", MSDOS_IMG, img], check=True)
    with open(os.path.join(tmp, "AUTOEXEC.BAT"), "wb") as f:
        f.write(b"@ECHO OFF\r\nPCNTPK INT=0x60\r\nDOSSHDS /SSH 10.0.2.15 %d /P:%s\r\n"
                % (PORT, PW.encode()))
    with open(os.path.join(tmp, "CONFIG.SYS"), "wb") as f:
        f.write(b"FILES=20\r\nBUFFERS=20\r\n")
    for src, dst in [(os.path.join(tmp, "AUTOEXEC.BAT"), "::AUTOEXEC.BAT"),
                     (os.path.join(tmp, "CONFIG.SYS"), "::CONFIG.SYS"),
                     (pcntpk, "::PCNTPK.COM"), (dosshds, "::DOSSHDS.EXE")]:
        r = subprocess.run(["mcopy", "-o", "-i", img, src, dst],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("FAIL: mcopy %s -> %s: %s (image full? needs ~160 KB free)"
                  % (src, dst, r.stderr.strip()), file=sys.stderr); return 1

    sock = os.path.join(tmp, "mon.sock")
    q = subprocess.Popen(
        ["qemu-system-i386", "-machine", "accel=kvm:tcg", "-m", "16", "-cpu", "pentium2",
         "-fda", img, "-boot", "a",
         "-netdev", "user,id=n0,hostfwd=tcp:127.0.0.1:%d-10.0.2.15:%d" % (PORT, PORT),
         "-device", "pcnet,netdev=n0,mac=52:54:00:12:34:56",
         "-display", "none", "-vga", "std", "-monitor", "unix:%s,server,nowait" % sock],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    mon = mon_factory(sock)
    rc = 1
    try:
        for _ in range(120):
            if os.path.exists(sock): break
            time.sleep(0.5)
        installed = False; dl = time.time() + 180
        while time.time() < dl:
            try:
                if "resident SSH console" in screen(mon): installed = True; break
            except Exception: pass
            time.sleep(3)
        print("e2e-ssh-msdos: SSH server installed on MS-DOS 6.22:", installed)
        if not installed:
            print("e2e-ssh-msdos: FAIL - DOSSHDS /SSH did not install", file=sys.stderr); return 1
        time.sleep(2)
        grid = AnsiGrid(); raw = bytearray(); lock = threading.Lock()
        p = subprocess.Popen(
            ["sshpass", "-p", PW, "ssh", "-tt", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1",
             "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "-p", str(PORT), "user@127.0.0.1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, preexec_fn=os.setsid)

        def rd():
            while True:
                c = p.stdout.read(4096)
                if not c: break
                with lock: raw.extend(c); grid.feed(c)
        threading.Thread(target=rd, daemon=True).start()
        for _ in range(120):
            with lock: got = len(raw) > 0
            if got or p.poll() is not None: break
            time.sleep(0.5)
        with lock: got = len(raw) > 0
        print("e2e-ssh-msdos: ssh authenticated + screen flowing:", got)
        if got and p.poll() is None:
            time.sleep(2)
            try: p.stdin.write(b"echo BANANA\r"); p.stdin.flush()
            except Exception: pass
            time.sleep(4)
            if "BANANA" in screen(mon):
                print("e2e-ssh-msdos: PASS - a stock ssh drove MS-DOS 6.22 "
                      "(auth + screen + keystrokes)"); rc = 0
            else:
                print("e2e-ssh-msdos: FAIL - BANANA not on the box screen", file=sys.stderr)
        else:
            print("e2e-ssh-msdos: FAIL - ssh got no screen", file=sys.stderr)
        try: os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception: pass
        return rc
    finally:
        try: os.killpg(os.getpgid(q.pid), signal.SIGTERM)
        except Exception: pass
        q.wait()


def _which(x):
    from shutil import which
    return which(x)


if __name__ == "__main__":
    sys.exit(main())
