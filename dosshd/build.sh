#!/bin/sh
# Build DOSSHD.EXE with Open Watcom (16-bit real-mode DOS target).
#
# Point WATCOM at an Open Watcom v2 install (the `ow-snapshot.tar.xz` from
# https://github.com/open-watcom/open-watcom-v2/releases extracted anywhere),
# or drop it in ~/tools/watcom and this script finds it.
set -e
cd "$(dirname "$0")"

: "${WATCOM:=$HOME/tools/watcom}"
export WATCOM
export PATH="$WATCOM/binl64:$WATCOM/binl:$PATH"
export INCLUDE="$WATCOM/h"
export EDPATH="$WATCOM/eddat"

if ! command -v wcl >/dev/null 2>&1; then
    echo "error: Open Watcom (wcl) not found. Set WATCOM to your install." >&2
    exit 1
fi

# -bcl=dos : compile+link, DOS target      -ms : small model (far ptrs explicit)
# -0       : 8086 (max compatibility)       -os : optimise for size
# -q/-zq   : quiet
#
# The packet receiver is a far routine the driver calls at interrupt time; it
# is written in assembly (pktrecv.asm) so the buffer hand-off and DS setup are
# exact. dosshd.c + net.c are the C parts.
wasm -zq -fo=pktrecv.obj pktrecv.asm
wcl -zq -bcl=dos -ms -0 -os -fe=dosshd.exe \
    dosshd.c net.c render.c cp437.c ansikey.c telnet.c pktrecv.obj

# DOS-friendly upper-case name
cp -f dosshd.exe DOSSHD.EXE 2>/dev/null || true

# ---- Crypto foundation (future SSH server) -------------------------------
# Vendored Monocypher (BSD-2 / CC0) + a public-domain SHA-256, wrapped in
# crypto/crypto.c. Two real-mode constraints shape how it is built:
#
#  1. SPEED: Monocypher's field arithmetic is 64-bit; on an 8086 (-0) every
#     64-bit op is a slow Watcom runtime call. So the crypto is compiled -3
#     (386 real mode: native 32-bit registers via operand-size prefixes, which
#     work in real mode). Consequence: the SSH feature needs a 386 or better;
#     plain DOSSHD stays -0/8086-clean.
#
#  2. CODE SIZE: even trimmed, Monocypher's 16-bit code will not fit a single
#     64K NEAR-code segment, so it cannot live in DOSSHD's small-model _TEXT.
#     It is therefore compiled MEDIUM model (-mm: FAR code in its own segment,
#     NEAR data shared with DOSSHD's DGROUP). The public API is marked __far
#     (see crypto.h) so small-model DOSSHD reaches it with a far call; near
#     data pointers pass straight through. The crypto uses no libc, so mixing
#     a medium-model module into a small-model link is clean.
#
# DOSSH_SSH_SUBSET additionally drops Monocypher features SSH does not use
# (Argon2, EdDSA<->X25519 conversions, "dirty" keys, Elligator 2, scalar
# division) to keep each module under the 64K per-segment limit. The native
# KAT build (test/run-tests.sh) defines the same macro so both agree.
CRYPTO_SRC="crypto/monocypher.c crypto/monocypher-ed25519.c crypto/sha256.c crypto/crypto.c"
CRYPTO_OBJ=""
for f in $CRYPTO_SRC; do
    o="${f%.c}.o"
    wcc -zq -bt=dos -mm -3 -os -zastd=c99 -dDOSSH_SSH_SUBSET -i=crypto -fo="$o" "$f"
    CRYPTO_OBJ="$CRYPTO_OBJ $o"
done

# Crypto self-test EXE. Built medium model (-mm) to match the crypto objects:
# an SSH-enabled DOSSHD is itself medium model (adding ~50K of crypto code
# already overflows the small-model near-code budget), so this is the faithful
# preview of that build. The base non-SSH DOSSHD above stays small model -0.
# Proves the -3 crypto objects compile AND link into a real DOS EXE clean;
# test/cryptot.c runs two of the known-answer vectors on target.
wcl -zq -bcl=dos -mm -3 -os -dDOSSH_SSH_SUBSET -i=crypto \
    -fe=cryptot.exe ../test/cryptot.c $CRYPTO_OBJ
cp -f cryptot.exe CRYPTOT.EXE 2>/dev/null || true

# VIDTEST: direct-video test fixture / demo app (see ../test/vidtest.c)
(cd ../test && wcl -zq -bcl=dos -ms -0 -os -fe=vidtest.exe vidtest.c \
    && cp -f vidtest.exe VIDTEST.EXE)

ls -l dosshd.exe DOSSHD.EXE CRYPTOT.EXE ../test/VIDTEST.EXE 2>/dev/null
echo "built dosshd/DOSSHD.EXE, dosshd/CRYPTOT.EXE and test/VIDTEST.EXE"
