#!/bin/sh
# Boot DOSSHD.EXE on FreeDOS under QEMU with COM1 bridged to a host TCP port,
# then render it from the host:
#
#   ./test/qemu-run.sh              # builds a floppy, launches QEMU
#   ./client/dossh 127.0.0.1 5555   # (in another terminal) watch the screen
#
# Needs: qemu-system-i386, mtools (mcopy), unzip, curl. Downloads a FreeDOS
# boot floppy on first run.
set -e
cd "$(dirname "$0")/.."

DOSSHD=${DOSSHD:-dosshd/DOSSHD.EXE}
PORT=${PORT:-5555}
[ -f "$DOSSHD" ] || { echo "build first: (cd dosshd && ./build.sh)"; exit 1; }

mkdir -p test/work && cd test/work
if [ ! -f FLOPPY.img ]; then
    echo "fetching FreeDOS boot floppy..."
    curl -sSLo FD12FLOPPY.zip \
      "https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/distributions/1.2/official/FD12FLOPPY.zip"
    unzip -o FD12FLOPPY.zip >/dev/null
fi

cp -f FLOPPY.img dosshd.img
# replace the FreeDOS installer's boot menu with a straight boot into DOSSHD
printf 'DOS=HIGH\r\nFILES=20\r\n' > FDCONFIG.SYS
printf '@ECHO OFF\r\nDOSSHD\r\n' > AUTOEXEC.BAT
mcopy -i dosshd.img -o FDCONFIG.SYS ::FDCONFIG.SYS
mcopy -i dosshd.img -o AUTOEXEC.BAT ::AUTOEXEC.BAT
mcopy -i dosshd.img -o "../../$DOSSHD" ::DOSSHD.EXE
# direct-video test app, if built (used by e2e-m3, handy for demos)
if [ -f ../VIDTEST.EXE ]; then
    mcopy -i dosshd.img -o ../VIDTEST.EXE ::VIDTEST.EXE
fi

echo "QEMU: COM1 -> tcp:127.0.0.1:$PORT  (connect with ./client/dossh)"
exec qemu-system-i386 -m 16 -fda dosshd.img -boot a \
    -serial "tcp:127.0.0.1:$PORT,server,nowait" \
    -display none -vga std
