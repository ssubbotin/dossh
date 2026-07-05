#!/usr/bin/env bash
# net-smoke.sh - end-to-end smoke test of the NDIS2/DIS_PKT network path.
#
# Builds a DOSSH network boot floppy with net/mkbootdisk.sh, boots it in QEMU
# behind an AMD PCnet NIC, connects over telnet, drives a keystroke, and checks
# the live screen came back. Runs the MS-DOS and FreeDOS cases independently.
#
# The DOS networking stack is vendor-supplied and not in this repo, so this test
# is opt-in: it SKIPS cleanly unless you point it at the pieces via env vars.
#
#   DOSSH_DRIVERS    dir with PROTMAN.DOS PROTMAN.EXE DIS_PKT.DOS NETBIND.COM
#                    PCNTND.DOS   (PCnet NDIS2 driver, DriverName PCNTND$)
#   DOSSH_MSDOS_IMG  a bootable MS-DOS 6.22 floppy image      (msdos case)
#   DOSSH_FD_IMG     a bootable FreeDOS 1.3+ floppy image     (freedos case)
#
# Needs: qemu-system-i386, mtools, python3. Exit 0 = every runnable case passed
# (skips do not fail); non-zero = a case failed.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$HERE")
MKB="$REPO/net/mkbootdisk.sh"
DOSSHD="$REPO/dosshd/DOSSHD.EXE"
DRIVERS=${DOSSH_DRIVERS:-}
PY=${PYTHON:-python3}

pass=0 fail=0 skip=0
need() { command -v "$1" >/dev/null 2>&1; }

if ! need qemu-system-i386 || ! need mcopy || ! need "$PY"; then
  echo "SKIP net-smoke: need qemu-system-i386, mtools and python3"; exit 0
fi
if [ -z "$DRIVERS" ] || [ ! -f "$DRIVERS/PCNTND.DOS" ]; then
  echo "SKIP net-smoke: set DOSSH_DRIVERS to a dir with the NDIS2 stack + PCNTND.DOS"
  echo "               (PROTMAN.DOS PROTMAN.EXE DIS_PKT.DOS NETBIND.COM PCNTND.DOS)"
  exit 0
fi
if [ ! -x "$DOSSHD" ] && [ ! -f "$DOSSHD" ]; then
  echo "SKIP net-smoke: build dosshd/DOSSHD.EXE first"; exit 0
fi

# run_case <os> <base-image> <hostport> <monport> <expect-substring>
run_case() {
  local os=$1 base=$2 hp=$3 mp=$4
  if [ -z "$base" ] || [ ! -f "$base" ]; then
    echo "SKIP  $os: no base image (set the env var to a bootable $os floppy)"; skip=$((skip+1)); return
  fi
  local img; img=$(mktemp --suffix=.img)
  echo "----- $os -----"
  if ! bash "$MKB" --os "$os" --base "$base" --nic-driver "$DRIVERS/PCNTND.DOS" \
        --drivername 'PCNTND$' --ip 10.0.2.15 --out "$img" \
        --stack "$DRIVERS" --dosshd "$DOSSHD" >/dev/null; then
    echo "FAIL  $os: mkbootdisk.sh failed"; fail=$((fail+1)); rm -f "$img"; return
  fi
  qemu-system-i386 -m 16 -fda "$img" -boot a \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$hp-:23" -device pcnet,netdev=n0 \
    -display none -monitor "telnet:127.0.0.1:$mp,server,nowait" >/dev/null 2>&1 &
  local qp=$!
  local out
  out=$(timeout 80 "$PY" - "$hp" <<'PYEOF'
import sys, socket, time
from ansiterm import AnsiGrid   # cwd is test/ (see cd below)
port = int(sys.argv[1])
g = AnsiGrid(); s = None
deadline = time.time() + 60
while time.time() < deadline and s is None:
    try:
        c = socket.create_connection(('127.0.0.1', port), timeout=2); c.settimeout(5)
        d = c.recv(4096)
        if d: g.feed(d); s = c
        else: c.close(); time.sleep(1)
    except (OSError, socket.timeout):
        time.sleep(1)
if s is None:
    print("NOCONSOLE"); sys.exit(0)
def wait_for(sub, t):
    e = time.time() + t; s.settimeout(0.5)
    while time.time() < e:
        if sub.lower() in g.text().lower(): return True
        try:
            d = s.recv(65536)
            if d: g.feed(d)
        except socket.timeout: pass
    return sub.lower() in g.text().lower()
wait_for('\\>', 20)                                    # let a DOS prompt appear
s.sendall(b'ECHO DOSSHNETOK\r')                        # inject a keystroke line...
print("OK" if wait_for('DOSSHNETOK', 10) else "NOMATCH")   # ...and see it mirrored
PYEOF
)
  kill "$qp" 2>/dev/null; wait "$qp" 2>/dev/null; rm -f "$img"
  case "$out" in
    *OK*)        echo "PASS  $os: console up, keystroke injected and mirrored"; pass=$((pass+1)) ;;
    *NOMATCH*)   echo "FAIL  $os: console up but injected keystroke not mirrored"; fail=$((fail+1)) ;;
    *NOCONSOLE*) echo "FAIL  $os: no telnet console on :$hp"; fail=$((fail+1)) ;;
    *)           echo "FAIL  $os: harness error ($out)"; fail=$((fail+1)) ;;
  esac
}

cd "$HERE"   # so the python heredoc can import ansiterm from this dir
run_case msdos   "${DOSSH_MSDOS_IMG:-}" 2401 5601
run_case freedos "${DOSSH_FD_IMG:-}"    2402 5602

echo "net-smoke: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
