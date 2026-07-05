#!/bin/sh
# e2e-ssh-pubkey.sh - prove the DOSSH SSH server (dosshd/ssh.c) authenticates a
# real OpenSSH client by PUBLICKEY (RFC 4252 sec 7, ssh-ed25519) with NO password
# on the wire, rejects an unauthorized key, and still allows password otherwise.
#
# Builds the native harness test/sshd_native.c (same ssh.c + crypto + rng the DOS
# target links) with an AUTHKEYS file holding a test ed25519 public key, then:
#   1. AUTHORIZED key, publickey only: assert ssh -vv shows it authenticated
#      using "publickey", a shell channel opens, the marker round-trips through
#      the encrypted channel, ssh exits 0 - and NO password was offered.
#   2. UNAUTHORIZED key, publickey only: assert ssh is rejected (non-zero exit,
#      the server grants no shell, the client never authenticates by publickey).
#   3. UNAUTHORIZED key + correct password (publickey,password): assert publickey
#      is denied and the client FALLS BACK to password and authenticates.
#   4. No key offered, password only: assert password auth still works.
#
# Needs a real `ssh` client, `ssh-keygen`, and `sshpass` (self-skips if missing).
set -e
cd "$(dirname "$0")/.."

if ! command -v ssh >/dev/null 2>&1; then
    echo "SKIP: no ssh client binary found" >&2
    exit 0
fi
if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "SKIP: ssh-keygen not found" >&2
    exit 0
fi
if ! command -v sshpass >/dev/null 2>&1; then
    echo "SKIP: sshpass not found (needed to drive password fallback)" >&2
    exit 0
fi

PW="hunter2-correct"
MARK="PUBKEYMARK-4252"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dossh-ssh-pubkey.XXXXXX")"
BIN="$WORK/sshd_native"
SRVPID=

cleanup() {
    [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build native SSH pubkey harness =="
cc -O2 -DDOSSH_SSH_SUBSET -DDOSSH_RNG_TEST -Idosshd/crypto -o "$BIN" \
    test/sshd_native.c dosshd/ssh.c \
    dosshd/crypto/crypto.c dosshd/crypto/sha256.c \
    dosshd/crypto/monocypher.c dosshd/crypto/monocypher-ed25519.c \
    dosshd/crypto/rng.c

echo "== generate test ed25519 keys =="
ssh-keygen -t ed25519 -N '' -q -f "$WORK/id_auth"   -C "authorized@dossh"
ssh-keygen -t ed25519 -N '' -q -f "$WORK/id_unauth" -C "unauthorized@dossh"
# AUTHKEYS holds ONLY the authorized key (standard authorized_keys format).
cp "$WORK/id_auth.pub" "$WORK/AUTHKEYS"

# Start the harness on a free loopback port (POSIX sh, no $RANDOM). Sets $PORT
# and $SRVPID. Args after the log are passed to sshd_native.
start_server() {
    _log="$1"; shift
    base=$(( 42000 + ($$ % 20000) ))
    PORT=""
    try=0
    while [ "$try" -lt 8 ]; do
        cand=$(( base + try * 149 ))
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

# IdentitiesOnly + IdentityAgent=none: offer ONLY the key named by -i, so the
# runner's ssh-agent can't inject extra keys that burn the server's retry budget
# and make these assertions nondeterministic.
COMMON="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o NumberOfPasswordPrompts=3 \
        -o IdentitiesOnly=yes -o IdentityAgent=none"

fail=0
need() {  # need <file> <label> <fixed-string>
    if grep -qF "$3" "$1"; then echo "  [PASS] $2: $3"
    else echo "  [FAIL] $2 missing: $3"; fail=1; fi
}
need_re() {  # need_re <file> <label> <regex>
    if grep -qE "$3" "$1"; then echo "  [PASS] $2: /$3/"
    else echo "  [FAIL] $2 missing: /$3/"; fail=1; fi
}
no_re() {  # no_re <file> <label> <regex>   (must NOT match)
    if grep -qE "$3" "$1"; then echo "  [FAIL] $2 unexpectedly present: /$3/"; fail=1
    else echo "  [PASS] $2 absent: /$3/"; fi
}

AUTHED_PUBKEY='Authenticated to .* using "publickey"|Authentication succeeded \(publickey\)'
AUTHED_PW='Authenticated to .* using "password"|Authentication succeeded \(password\)'

# ---------------------------------------------------------------------------
echo "== 1. AUTHORIZED key, publickey only: no-password login + channel echo =="
SRV_LOG="$WORK/srv-good.log"; SSH_LOG="$WORK/ssh-good.log"; SSH_OUT="$WORK/ssh-good.out"
start_server "$SRV_LOG" --authkeys="$WORK/AUTHKEYS" --pass="$PW"
echo "-- server on 127.0.0.1:$PORT --"
need "$SRV_LOG" server "loaded 1 authorized ed25519 key"

set +e
printf '%s\r' "$MARK" | timeout 25 ssh -vv -tt $COMMON \
    -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
    -i "$WORK/id_auth" -p "$PORT" tester@127.0.0.1 > "$SSH_OUT" 2> "$SSH_LOG"
SSH_RC=$?
set -e
echo "-- ssh exit code: $SSH_RC --"
SRV_RC=0; wait "$SRVPID" 2>/dev/null || SRV_RC=$?; SRVPID=

echo "-- assertions (server) --"
need    "$SRV_LOG" server "USERAUTH SUCCESS"
need    "$SRV_LOG" server "SHELL READY (pty=1"
need    "$SRV_LOG" server "RESULT: PASS"
echo "-- assertions (ssh -vv client) --"
need_re "$SSH_LOG" client "$AUTHED_PUBKEY"
need_re "$SSH_LOG" client 'Server accepts key|Offering public key'
no_re   "$SSH_LOG" client 'Next authentication method: password|Trying private key.*password'
if [ "$SSH_RC" -eq 0 ]; then echo "  [PASS] ssh exit 0 (clean channel close)"
else echo "  [FAIL] ssh exit $SSH_RC (expected 0)"; fail=1; fi
if [ "$SRV_RC" -eq 0 ]; then echo "  [PASS] server exit 0"
else echo "  [FAIL] server exit $SRV_RC"; fail=1; fi
echo "-- assertions (channel data round-trip) --"
need    "$SSH_OUT" echo "DOSSH interactive shell ready"
need    "$SSH_OUT" echo "$MARK"

# ---------------------------------------------------------------------------
echo "== 2. UNAUTHORIZED key, publickey only: rejected =="
SRV_LOG2="$WORK/srv-bad.log"; SSH_LOG2="$WORK/ssh-bad.log"
start_server "$SRV_LOG2" --authkeys="$WORK/AUTHKEYS" --pass="$PW"
echo "-- server on 127.0.0.1:$PORT --"

set +e
timeout 25 ssh -vv -tt $COMMON \
    -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes \
    -i "$WORK/id_unauth" -p "$PORT" tester@127.0.0.1 true < /dev/null \
    > /dev/null 2> "$SSH_LOG2"
SSH_RC2=$?
set -e
echo "-- ssh exit code: $SSH_RC2 (non-zero expected) --"
kill "$SRVPID" 2>/dev/null || true; wait "$SRVPID" 2>/dev/null || true; SRVPID=

echo "-- assertions (unauthorized key rejected) --"
if [ "$SSH_RC2" -ne 0 ]; then echo "  [PASS] ssh rejected (exit $SSH_RC2)"
else echo "  [FAIL] ssh exit 0 on an unauthorized key"; fail=1; fi
no_re   "$SSH_LOG2" client "$AUTHED_PUBKEY"
need_re "$SSH_LOG2" client 'Permission denied|Disconnected|Too many authentication'
if grep -qF "SHELL READY" "$SRV_LOG2"; then
    echo "  [FAIL] server granted a shell to an unauthorized key"; fail=1
else echo "  [PASS] server granted no shell to an unauthorized key"; fi

# ---------------------------------------------------------------------------
echo "== 3. UNAUTHORIZED key + correct password: publickey denied, password wins =="
SRV_LOG3="$WORK/srv-fb.log"; SSH_LOG3="$WORK/ssh-fb.log"
start_server "$SRV_LOG3" --authkeys="$WORK/AUTHKEYS" --pass="$PW"
echo "-- server on 127.0.0.1:$PORT --"

set +e
timeout 25 sshpass -p "$PW" ssh -vv -tt $COMMON \
    -o PreferredAuthentications=publickey,password -o PubkeyAuthentication=yes \
    -i "$WORK/id_unauth" -p "$PORT" tester@127.0.0.1 true < /dev/null \
    > /dev/null 2> "$SSH_LOG3"
SSH_RC3=$?
set -e
echo "-- ssh exit code: $SSH_RC3 --"
wait "$SRVPID" 2>/dev/null || true; SRVPID=

echo "-- assertions (fallback to password) --"
no_re   "$SSH_LOG3" client "$AUTHED_PUBKEY"
need_re "$SSH_LOG3" client "$AUTHED_PW"
need    "$SRV_LOG3" server "SHELL READY (pty=1"

# ---------------------------------------------------------------------------
echo "== 4. No key offered, password only: password auth still works =="
SRV_LOG4="$WORK/srv-pw.log"; SSH_LOG4="$WORK/ssh-pw.log"
start_server "$SRV_LOG4" --authkeys="$WORK/AUTHKEYS" --pass="$PW"
echo "-- server on 127.0.0.1:$PORT --"

set +e
timeout 25 sshpass -p "$PW" ssh -vv -tt $COMMON \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -p "$PORT" tester@127.0.0.1 true < /dev/null > /dev/null 2> "$SSH_LOG4"
SSH_RC4=$?
set -e
echo "-- ssh exit code: $SSH_RC4 --"
wait "$SRVPID" 2>/dev/null || true; SRVPID=

echo "-- assertions (password still works) --"
need_re "$SSH_LOG4" client "$AUTHED_PW"
need    "$SRV_LOG4" server "SHELL READY (pty=1"
if [ "$SSH_RC4" -eq 0 ]; then echo "  [PASS] ssh exit 0 (password auth)"
else echo "  [FAIL] ssh exit $SSH_RC4 (expected 0)"; fail=1; fi

# ---------------------------------------------------------------------------
if [ "$fail" -ne 0 ]; then
    echo
    echo "FAILED."
    echo "good server log:";   sed 's/^/  srv | /' "$SRV_LOG"
    echo "good ssh -vv tail:"; tail -25 "$SSH_LOG" | sed 's/^/  ssh | /'
    echo "bad ssh -vv tail:";  tail -15 "$SSH_LOG2" | sed 's/^/  bad | /'
    exit 1
fi

echo
echo "== SSH publickey userauth interop PASSED =="
