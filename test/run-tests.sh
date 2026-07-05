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

echo "== unit: server key map (test_ansikey.c) =="
cc -o "$BIN" dosshd/ansikey.c test/test_ansikey.c
"$BIN"

[ "$1" = "unit" ] && { echo "== unit tests passed =="; exit 0; }

echo "== e2e (QEMU, sequential) =="
for t in e2e-m5a e2e-m5b e2e-m5c e2e-m5-multiclient e2e-m5d-reconnect e2e-m3; do
    echo "-- $t --"
    python3 "test/$t.py" || { echo "FAILED: $t"; exit 1; }
done

# Opt-in NDIS2/DIS_PKT smoke test - builds a net floppy with net/mkbootdisk.sh
# and drives DOSSHD over an emulated NIC. Skips unless DOSSH_DRIVERS is set (the
# DOS networking stack is vendor-supplied; see docs/NETWORKING.md).
echo "== net-smoke (opt-in via DOSSH_DRIVERS) =="
bash test/net-smoke.sh || { echo "FAILED: net-smoke"; exit 1; }

echo "== all tests passed =="
