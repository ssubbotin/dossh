#!/bin/sh
# Boot DOSSHD.EXE on FreeDOS under QEMU and expose it to a host TCP port. DOSSHD
# speaks telnet/ANSI, so connect with any terminal: `telnet 127.0.0.1 $PORT`,
# `nc 127.0.0.1 $PORT`, or PuTTY in raw/telnet mode.
#
# Two transports (TRANSPORT env, default serial):
#
#   TRANSPORT=serial  (default) COM1 bridged to tcp:127.0.0.1:$PORT; DOSSHD
#                     mirrors over the serial line as raw ANSI.
#   TRANSPORT=pkt     an emulated PCnet NIC + the PCNTPK packet driver; DOSSHD
#                     /NET listens with its own TCP stack (telnet), and QEMU
#                     user-net forwards host tcp:$PORT to the guest.
#
#   ./test/qemu-run.sh                    # serial
#   TRANSPORT=pkt ./test/qemu-run.sh      # packet driver + TCP
#   telnet 127.0.0.1 5555                 # (either) watch / drive the screen
#
# Needs: qemu-system-i386, mtools (mcopy), unzip, curl. Downloads a FreeDOS
# boot floppy and (pkt mode) the PCnet packet driver on first run.
set -e
cd "$(dirname "$0")/.."

DOSSHD=${DOSSHD:-dosshd/DOSSHD.EXE}
PORT=${PORT:-5555}
TRANSPORT=${TRANSPORT:-serial}
GUEST_IP=${GUEST_IP:-10.0.2.15}
[ -f "$DOSSHD" ] || { echo "build first: (cd dosshd && ./build.sh)"; exit 1; }

mkdir -p test/work && cd test/work
if [ ! -f FLOPPY.img ]; then
    echo "fetching FreeDOS boot floppy..."
    curl -sSLo FD12FLOPPY.zip \
      "https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/distributions/1.2/official/FD12FLOPPY.zip"
    unzip -o FD12FLOPPY.zip >/dev/null
fi

cp -f FLOPPY.img dosshd.img
printf 'DOS=HIGH\r\nFILES=20\r\n' > FDCONFIG.SYS

if [ "$TRANSPORT" = pkt ]; then
    # AMD PCnet DOS packet driver (PCNTPK.COM) for QEMU's emulated pcnet NIC.
    # A separate, freely-redistributable tool used only to bring the NIC up;
    # never linked into (MIT) DOSSHD. PCnet is chosen because its send_pkt is a
    # blind bus-master DMA hand-off that transmits from interrupt/TSR context
    # (the NE2000's shared remote-DMA send does not - see docs/DESIGN.md).
    if [ ! -f PCNTPK.COM ]; then
        echo "fetching AMD PCnet packet driver (PCNTPK.COM)..."
        curl -sSLo amdnic_2.zip "https://packetdriversdos.net/ZIP/amdnic_2.zip"
        unzip -oj amdnic_2.zip "PKTDRVR/PCNTPK.COM" >/dev/null
    fi
    # load the packet driver at INT 0x60 (auto-detects the PCI NIC), then /NET.
    # PW=<pw> (optional) gates the console with a password (/P:<pw>).
    PWARG=""
    [ -n "$PW" ] && PWARG=" /P:$PW"
    printf '@ECHO OFF\r\nPCNTPK INT=0x60\r\nDOSSHD /NET %s %s%s\r\n' \
        "$GUEST_IP" "$PORT" "$PWARG" > AUTOEXEC.BAT
    mcopy -i dosshd.img -o PCNTPK.COM ::PCNTPK.COM
else
    printf '@ECHO OFF\r\nDOSSHD\r\n' > AUTOEXEC.BAT
fi

mcopy -i dosshd.img -o FDCONFIG.SYS ::FDCONFIG.SYS
mcopy -i dosshd.img -o AUTOEXEC.BAT ::AUTOEXEC.BAT
mcopy -i dosshd.img -o "../../$DOSSHD" ::DOSSHD.EXE
# direct-video test app, if built (used by e2e-m3, handy for demos)
if [ -f ../VIDTEST.EXE ]; then
    mcopy -i dosshd.img -o ../VIDTEST.EXE ::VIDTEST.EXE
fi

# optional QEMU monitor socket (set MON=/path/to.sock) for tests that inspect
# guest state (e.g. dumping VRAM with `xp`).
MONARG=""
[ -n "$MON" ] && MONARG="-monitor unix:$MON,server,nowait"

if [ "$TRANSPORT" = pkt ]; then
    echo "QEMU: PCnet + DOSSHD /NET, host tcp:127.0.0.1:$PORT -> guest $GUEST_IP:$PORT"
    exec qemu-system-i386 -m 16 -fda dosshd.img -boot a \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-$GUEST_IP:$PORT" \
        -device "pcnet,netdev=n0,mac=52:54:00:12:34:56" \
        -display none -vga std $MONARG
else
    echo "QEMU: COM1 -> tcp:127.0.0.1:$PORT  (connect with telnet/nc)"
    exec qemu-system-i386 -m 16 -fda dosshd.img -boot a \
        -serial "tcp:127.0.0.1:$PORT,server,nowait" \
        -display none -vga std $MONARG
fi
