#!/bin/sh
# e2e-ssh-transport.sh - prove the DOSSH SSH transport (dosshd/ssh.c)
# interoperates with a stock OpenSSH client.
#
# Builds the native harness test/sshd_native.c (same ssh.c + crypto + rng the
# DOS target links), runs it on a loopback port, points a real `ssh -vv` at it,
# and asserts from BOTH logs that:
#   - the client accepted curve25519-sha256 kex + the ssh-ed25519 host key,
#   - both sides switched to chacha20-poly1305@openssh.com (NEWKEYS),
#   - the server DECRYPTED the client's SSH_MSG_SERVICE_REQUEST "ssh-userauth",
#   - the client DECRYPTED our encrypted SSH_MSG_SERVICE_ACCEPT.
#
# The ssh invocation is EXPECTED to exit non-zero: it reaches userauth (the next
# layer, not built) with PreferredAuthentications=none and is denied. That is a
# success for the transport, which is all this test covers.
set -e
cd "$(dirname "$0")/.."

if ! command -v ssh >/dev/null 2>&1; then
    echo "SKIP: no ssh client binary found" >&2
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dossh-ssh-e2e.XXXXXX")"
BIN="$WORK/sshd_native"
SRV_LOG="$WORK/server.log"
SSH_LOG="$WORK/ssh.log"

cleanup() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build native SSH transport harness =="
cc -O2 -DDOSSH_SSH_SUBSET -DDOSSH_RNG_TEST -Idosshd/crypto -o "$BIN" \
    test/sshd_native.c dosshd/ssh.c \
    dosshd/crypto/crypto.c dosshd/crypto/sha256.c \
    dosshd/crypto/monocypher.c dosshd/crypto/monocypher-ed25519.c \
    dosshd/crypto/rng.c

# Pick a loopback port; retry a few if the bind is taken (POSIX sh, no $RANDOM).
base=$(( 40000 + ($$ % 20000) ))
PORT=""
try=0
while [ "$try" -lt 8 ]; do
    cand=$(( base + try * 111 ))
    "$BIN" "$cand" > "$SRV_LOG" 2>&1 &
    SRVPID=$!
    i=0
    while [ "$i" -lt 30 ]; do
        grep -q "^listening on " "$SRV_LOG" 2>/dev/null && { PORT="$cand"; break; }
        kill -0 "$SRVPID" 2>/dev/null || break     # server died (bind failed)
        i=$((i + 1)); sleep 0.1
    done
    [ -n "$PORT" ] && break
    kill "$SRVPID" 2>/dev/null || true
    wait "$SRVPID" 2>/dev/null || true
    SRVPID=
    try=$((try + 1))
done
[ -z "$PORT" ] && { echo "server did not start on any port"; cat "$SRV_LOG"; exit 1; }
echo "== server listening on 127.0.0.1:$PORT =="

echo "== drive a real ssh -vv client (auth is expected to fail) =="
set +e
ssh -vv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=none -o BatchMode=yes \
    -p "$PORT" x@127.0.0.1 true > "$SSH_LOG" 2>&1
SSH_RC=$?
set -e
echo "ssh client exit code: $SSH_RC (non-zero is expected - auth not implemented)"

wait "$SRVPID"; SRV_RC=$?
SRVPID=

fail=0
need_srv() {
    if grep -qF "$1" "$SRV_LOG"; then echo "  [PASS] server: $1"
    else echo "  [FAIL] server log missing: $1"; fail=1; fi
}
need_ssh() {
    if grep -qF "$1" "$SSH_LOG"; then echo "  [PASS] client: $1"
    else echo "  [FAIL] ssh -vv missing: $1"; fail=1; fi
}

echo "== assertions (server side) =="
need_srv "kex complete: curve25519-sha256 + ssh-ed25519"
need_srv "SENT KEX_ECDH_REPLY + NEWKEYS"
need_srv "DECRYPTED SERVICE_REQUEST: ssh-userauth"
need_srv "RESULT: PASS"
if [ "$SRV_RC" -ne 0 ]; then echo "  [FAIL] server exit code $SRV_RC"; fail=1;
else echo "  [PASS] server exit code 0"; fi

echo "== assertions (ssh -vv client side) =="
need_ssh "kex: algorithm: curve25519-sha256"
need_ssh "kex: host key algorithm: ssh-ed25519"
need_ssh "SSH2_MSG_KEX_ECDH_REPLY received"
need_ssh "Server host key: ssh-ed25519"
need_ssh "SSH2_MSG_NEWKEYS received"
need_ssh "SSH2_MSG_SERVICE_ACCEPT received"

if [ "$fail" -ne 0 ]; then
    echo
    echo "FAILED. Server log:"; sed 's/^/  srv| /' "$SRV_LOG"
    echo "ssh -vv tail:"; tail -25 "$SSH_LOG" | sed 's/^/  ssh| /'
    exit 1
fi

echo
echo "== SSH transport interop PASSED =="
