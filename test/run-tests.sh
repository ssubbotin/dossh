#!/bin/sh
# Run the DOSSH test suite.
#
#   ./test/run-tests.sh          # build + native unit tests + all QEMU e2e tests
#   ./test/run-tests.sh unit     # native unit tests only (fast, no QEMU)
#
# The e2e tests boot DOSSHD under QEMU and share one floppy image, so they run
# SEQUENTIALLY - do not parallelise them. Needs qemu-system-i386 + mtools.
set -e
cd "$(dirname "$0")/.."
BIN="${TMPDIR:-/tmp}/dossh-test-ansikey"

echo "== build DOSSHD =="
( cd dosshd && ./build.sh >/dev/null )

# SSH transport interop target: needs a real `ssh` binary, so it is kept out of
# the pure-`unit` path. Runs the native harness against a stock OpenSSH client.
if [ "$1" = "ssh" ]; then
    echo "== ssh transport interop (real OpenSSH client) =="
    bash test/e2e-ssh-transport.sh
    echo "== ssh userauth + session-channel interop (real OpenSSH client) =="
    bash test/e2e-ssh-shell.sh
    echo "== ssh targets passed =="
    exit 0
fi

echo "== unit: server key map (test_ansikey.c) =="
cc -o "$BIN" dosshd/ansikey.c test/test_ansikey.c
"$BIN"

echo "== unit: crypto known-answer tests (test_crypto.c) =="
CBIN="${TMPDIR:-/tmp}/dossh-test-crypto"
# Same crypto .c files the DOS build uses; DOSSH_SSH_SUBSET matches build.sh so
# the vendored Monocypher subset is identical on host and target.
cc -O2 -DDOSSH_SSH_SUBSET -Idosshd/crypto -o "$CBIN" \
    test/test_crypto.c dosshd/crypto/crypto.c dosshd/crypto/sha256.c \
    dosshd/crypto/monocypher.c dosshd/crypto/monocypher-ed25519.c
"$CBIN"

echo "== unit: RNG DRBG KAT + distribution (test_rng.c) =="
RBIN="${TMPDIR:-/tmp}/dossh-test-rng"
# Same rng.c + crypto the DOS build links; -DDOSSH_RNG_TEST enables the
# deterministic fixed-seed hook the DRBG known-answer test needs.
cc -O2 -DDOSSH_SSH_SUBSET -DDOSSH_RNG_TEST -Idosshd/crypto -o "$RBIN" \
    test/test_rng.c dosshd/crypto/rng.c dosshd/crypto/crypto.c dosshd/crypto/sha256.c \
    dosshd/crypto/monocypher.c dosshd/crypto/monocypher-ed25519.c
"$RBIN"

[ "$1" = "unit" ] && { echo "== unit tests passed =="; exit 0; }

echo "== e2e (QEMU, sequential) =="
for t in e2e-m5a e2e-m5b e2e-m5c e2e-m5-multiclient e2e-auth e2e-naws e2e-m5d-reconnect e2e-reboot e2e-m3; do
    echo "-- $t --"
    python3 "test/$t.py" || { echo "FAILED: $t"; exit 1; }
done

# Native in-DOS SSH acceptance test (the P1 milestone): a stock `ssh` client
# drives a FreeDOS console whose SSH crypto terminates on the DOS box. Boots the
# SSH-enabled DOSSHDS.EXE under QEMU (Pentium CPU) and connects a real ssh
# client. Self-skips if ssh/sshpass/DOSSHDS are absent. Set SSH_TRANSPORT=sshser
# to exercise the same server over COM1 (a serial-bridge) where QEMU user-net is
# unavailable.
echo "-- e2e-ssh-dos --"
python3 test/e2e-ssh-dos.py || { echo "FAILED: e2e-ssh-dos"; exit 1; }

# Opt-in NDIS2/DIS_PKT smoke test - builds a net floppy with net/mkbootdisk.sh
# and drives DOSSHD over an emulated NIC. Skips unless DOSSH_DRIVERS is set (the
# DOS networking stack is vendor-supplied; see docs/NETWORKING.md).
echo "== net-smoke (opt-in via DOSSH_DRIVERS) =="
bash test/net-smoke.sh || { echo "FAILED: net-smoke"; exit 1; }

# SSH interop against a real OpenSSH client (self-skips if `ssh`/`sshpass` are
# absent). Needs cc + ssh, not QEMU, so it runs in the default sweep too.
echo "== ssh transport interop (real OpenSSH client) =="
bash test/e2e-ssh-transport.sh || { echo "FAILED: ssh transport interop"; exit 1; }

echo "== ssh userauth + session-channel interop (real OpenSSH client) =="
bash test/e2e-ssh-shell.sh || { echo "FAILED: ssh userauth+channel interop"; exit 1; }

echo "== all tests passed =="
