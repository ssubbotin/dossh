#!/bin/sh
# e2e-ssh-shell.sh - prove the DOSSH SSH server (dosshd/ssh.c) carries a real
# OpenSSH client all the way through PASSWORD userauth and a session channel,
# and that channel data round-trips in BOTH directions over the encrypted
# transport.
#
# Builds the native harness test/sshd_native.c (same ssh.c + crypto + rng the
# DOS target links) in --shell mode: after the shell request is granted it
# echoes every byte the client types. Then:
#   1. GOOD password: sshpass drives `ssh -tt` non-interactively, we pipe a
#      marker line, and assert:
#        - ssh -vv shows password auth succeeded,
#        - a session channel + shell was opened (server log),
#        - the marker piped to the shell is ECHOED back through the channel,
#        - ssh exits 0 (clean channel close with exit-status).
#   2. WRONG password: assert ssh is rejected (non-zero exit, no shell).
#
# Needs a real `ssh` client and `sshpass` (self-skips if either is missing).
set -e
cd "$(dirname "$0")/.."

if ! command -v ssh >/dev/null 2>&1; then
    echo "SKIP: no ssh client binary found" >&2
    exit 0
fi
if ! command -v sshpass >/dev/null 2>&1; then
    echo "SKIP: sshpass not found (needed to drive password auth non-interactively)" >&2
    exit 0
fi

PW="hunter2-correct"
MARK="ECHOMARK-31337"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dossh-ssh-shell.XXXXXX")"
BIN="$WORK/sshd_native"
SRVPID=

cleanup() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build native SSH shell harness =="
cc -O2 -DDOSSH_SSH_SUBSET -DDOSSH_RNG_TEST -Idosshd/crypto -o "$BIN" \
    test/sshd_native.c dosshd/ssh.c \
    dosshd/crypto/crypto.c dosshd/crypto/sha256.c \
    dosshd/crypto/monocypher.c dosshd/crypto/monocypher-ed25519.c \
    dosshd/crypto/rng.c

# Start the harness on a free loopback port (POSIX sh, no $RANDOM). Sets $PORT
# and $SRVPID. Args after the base are passed to sshd_native (e.g. --pass=...).
start_server() {
    _log="$1"; shift
    base=$(( 41000 + ($$ % 20000) ))
    PORT=""
    try=0
    while [ "$try" -lt 8 ]; do
        cand=$(( base + try * 137 ))
        "$BIN" "$cand" "$@" > "$_log" 2>&1 &
        SRVPID=$!
        i=0
        while [ "$i" -lt 30 ]; do
            grep -q "^listening on " "$_log" 2>/dev/null && { PORT="$cand"; break; }
            kill -0 "$SRVPID" 2>/dev/null || break
            i=$((i + 1)); sleep 0.1
        done
        [ -n "$PORT" ] && break
        kill "$SRVPID" 2>/dev/null || true
        wait "$SRVPID" 2>/dev/null || true
        SRVPID=
        try=$((try + 1))
        base=$(( base + 1 ))
    done
    [ -z "$PORT" ] && { echo "server did not start"; cat "$_log"; exit 1; }
    return 0
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o PreferredAuthentications=password -o PubkeyAuthentication=no \
          -o NumberOfPasswordPrompts=3"

fail=0
need() {  # need <file> <label> <fixed-string>
    if grep -qF "$3" "$1"; then echo "  [PASS] $2: $3"
    else echo "  [FAIL] $2 missing: $3"; fail=1; fi
}
need_re() {  # need_re <file> <label> <regex>
    if grep -qE "$3" "$1"; then echo "  [PASS] $2: /$3/"
    else echo "  [FAIL] $2 missing: /$3/"; fail=1; fi
}

# ---------------------------------------------------------------------------
echo "== 1. GOOD password: full auth + shell + bidirectional channel echo =="
SRV_LOG="$WORK/srv-good.log"
SSH_LOG="$WORK/ssh-good.log"
SSH_OUT="$WORK/ssh-good.out"
start_server "$SRV_LOG" "--pass=$PW"
echo "-- server on 127.0.0.1:$PORT --"

set +e
printf '%s\r' "$MARK" | timeout 20 sshpass -p "$PW" ssh -vv -tt $SSH_OPTS \
    -p "$PORT" tester@127.0.0.1 > "$SSH_OUT" 2> "$SSH_LOG"
SSH_RC=$?
set -e
echo "-- ssh exit code: $SSH_RC --"
SRV_RC=0; wait "$SRVPID" 2>/dev/null || SRV_RC=$?
SRVPID=

echo "-- assertions (server) --"
need    "$SRV_LOG" server "DECRYPTED SERVICE_REQUEST: ssh-userauth"
need    "$SRV_LOG" server "USERAUTH SUCCESS"
need    "$SRV_LOG" server "SHELL READY (pty=1"
need    "$SRV_LOG" server "RESULT: PASS"
if [ "$SRV_RC" -eq 0 ]; then echo "  [PASS] server exit code 0"
else echo "  [FAIL] server exit code $SRV_RC"; fail=1; fi

echo "-- assertions (ssh -vv client) --"
need_re "$SSH_LOG" client 'Authentication succeeded \(password\)|Authenticated to .* using "password"'
need_re "$SSH_LOG" client 'shell request accepted|Sending environment'
if [ "$SSH_RC" -eq 0 ]; then echo "  [PASS] ssh exit code 0 (clean channel close)"
else echo "  [FAIL] ssh exit code $SSH_RC (expected 0)"; fail=1; fi

echo "-- assertions (channel data round-trip) --"
# The marker was piped INTO the shell and must come BACK out the channel (echo).
need    "$SSH_OUT" echo "DOSSH interactive shell ready"
need    "$SSH_OUT" echo "$MARK"

# ---------------------------------------------------------------------------
echo "== 2. WRONG password: client is rejected =="
SRV_LOG2="$WORK/srv-bad.log"
SSH_LOG2="$WORK/ssh-bad.log"
start_server "$SRV_LOG2" "--pass=$PW"
echo "-- server on 127.0.0.1:$PORT --"

set +e
timeout 20 sshpass -p "wrong-password-xyz" ssh -vv -tt $SSH_OPTS \
    -p "$PORT" tester@127.0.0.1 true < /dev/null > /dev/null 2> "$SSH_LOG2"
SSH_RC2=$?
set -e
echo "-- ssh exit code: $SSH_RC2 (non-zero expected) --"
wait "$SRVPID" 2>/dev/null || true; SRVPID=

echo "-- assertions (wrong password rejected) --"
if [ "$SSH_RC2" -ne 0 ]; then echo "  [PASS] ssh rejected (exit $SSH_RC2)"
else echo "  [FAIL] ssh exit 0 on wrong password"; fail=1; fi
need_re "$SSH_LOG2" client 'Permission denied|Disconnected|Too many authentication'
if grep -qF "SHELL READY" "$SRV_LOG2"; then
    echo "  [FAIL] server granted a shell on a wrong password"; fail=1
else echo "  [PASS] server granted no shell on a wrong password"; fi

# ---------------------------------------------------------------------------
if [ "$fail" -ne 0 ]; then
    echo
    echo "FAILED."
    echo "good server log:"; sed 's/^/  srv| /' "$SRV_LOG"
    echo "good ssh stdout:"; cat -v "$SSH_OUT" | sed 's/^/  out| /'
    echo "good ssh -vv tail:"; tail -20 "$SSH_LOG" | sed 's/^/  ssh| /'
    echo "bad server log:"; sed 's/^/  bad| /' "$SRV_LOG2"
    exit 1
fi

echo
echo "== SSH userauth + session-channel interop PASSED =="
