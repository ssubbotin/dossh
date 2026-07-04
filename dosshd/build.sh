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
wcl -zq -bcl=dos -ms -0 -os -fe=dosshd.exe dosshd.c

# DOS-friendly upper-case name
cp -f dosshd.exe DOSSHD.EXE 2>/dev/null || true

# VIDTEST: direct-video test fixture / demo app (see ../test/vidtest.c)
(cd ../test && wcl -zq -bcl=dos -ms -0 -os -fe=vidtest.exe vidtest.c \
    && cp -f vidtest.exe VIDTEST.EXE)

ls -l dosshd.exe DOSSHD.EXE ../test/VIDTEST.EXE 2>/dev/null
echo "built dosshd/DOSSHD.EXE and test/VIDTEST.EXE"
