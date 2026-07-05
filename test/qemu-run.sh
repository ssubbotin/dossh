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

PORT=${PORT:-5555}
TRANSPORT=${TRANSPORT:-serial}
GUEST_IP=${GUEST_IP:-10.0.2.15}
# Prefer KVM (fast boot), fall back to TCG software emulation where KVM is
# unavailable. Override with e.g. QEMU_ACCEL=tcg to force pure emulation.
QEMU_ACCEL=${QEMU_ACCEL:-kvm:tcg}
# TRANSPORT=ssh boots the SSH-enabled DOSSHDS.EXE (native in-DOS SSH server); it
# rides the same PCnet packet driver + hostfwd path as pkt, but a stock `ssh`
# client terminates the crypto on the DOS box. Needs a 386 (crypto) + 586 (rng
# RDTSC), so it runs on a Pentium CPU.
case "$TRANSPORT" in
ssh|sshser)                             # SSH build (TCP or COM1)
    DOSSHD=${DOSSHD:-dosshd/DOSSHDS.EXE}
    EXE_NAME=DOSSHDS.EXE ;;
*)
    DOSSHD=${DOSSHD:-dosshd/DOSSHD.EXE}
    EXE_NAME=DOSSHD.EXE ;;
esac
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

# The SSH build (DOSSHDS.EXE) is ~130 KB but the FreeDOS install floppy has only
# ~90 KB free. We never boot the installer, so drop its payload to make room.
case "$TRANSPORT" in
ssh|sshser)
    mdeltree -i dosshd.img ::/FDSETUP >/dev/null 2>&1 || true
    mdel     -i dosshd.img ::SETUP.BAT >/dev/null 2>&1 || true ;;
esac

case "$TRANSPORT" in
pkt|ssh)
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
    # load the packet driver at INT 0x60 (auto-detects the PCI NIC), then the
    # server. PW=<pw> (optional) gates the console with a password (/P:<pw>).
    PWARG=""
    [ -n "$PW" ] && PWARG=" /P:$PW"
    if [ "$TRANSPORT" = ssh ]; then
        printf '@ECHO OFF\r\nPCNTPK INT=0x60\r\nDOSSHDS /SSH %s %s%s\r\n' \
            "$GUEST_IP" "$PORT" "$PWARG" > AUTOEXEC.BAT
    else
        printf '@ECHO OFF\r\nPCNTPK INT=0x60\r\nDOSSHD /NET %s %s%s\r\n' \
            "$GUEST_IP" "$PORT" "$PWARG" > AUTOEXEC.BAT
    fi
    mcopy -i dosshd.img -o PCNTPK.COM ::PCNTPK.COM
    ;;
sshser)
    # SSH over COM1: no NIC/driver. QEMU bridges COM1 to a host TCP port, so a
    # stock `ssh` pointed at that port speaks SSH straight to the DOS box. PW
    # (optional) sets the password (/P:<pw>).
    PWARG=""
    [ -n "$PW" ] && PWARG=" /P:$PW"
    printf '@ECHO OFF\r\nDOSSHDS /SSH /COM%s\r\n' "$PWARG" > AUTOEXEC.BAT
    ;;
*)
    printf '@ECHO OFF\r\nDOSSHD\r\n' > AUTOEXEC.BAT
    ;;
esac

mcopy -i dosshd.img -o FDCONFIG.SYS ::FDCONFIG.SYS
mcopy -i dosshd.img -o AUTOEXEC.BAT ::AUTOEXEC.BAT
mcopy -i dosshd.img -o "../../$DOSSHD" ::$EXE_NAME
# direct-video test app, if built (used by e2e-m3, handy for demos)
if [ -f ../VIDTEST.EXE ]; then
    mcopy -i dosshd.img -o ../VIDTEST.EXE ::VIDTEST.EXE
fi

# optional QEMU monitor socket (set MON=/path/to.sock) for tests that inspect
# guest state (e.g. dumping VRAM with `xp`).
MONARG=""
[ -n "$MON" ] && MONARG="-monitor unix:$MON,server,nowait"

case "$TRANSPORT" in
pkt|ssh)
    # SSH crypto needs a 386 (Monocypher -3) and rng needs RDTSC (586), so boot
    # the SSH build on a Pentium. pkt (telnet) stays on the default CPU.
    CPUARG=""
    [ "$TRANSPORT" = ssh ] && CPUARG="-cpu pentium2"
    echo "QEMU: PCnet + $EXE_NAME, host tcp:127.0.0.1:$PORT -> guest $GUEST_IP:$PORT"
    exec qemu-system-i386 -machine accel=$QEMU_ACCEL -m 16 $CPUARG -fda dosshd.img -boot a \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-$GUEST_IP:$PORT" \
        -device "pcnet,netdev=n0,mac=52:54:00:12:34:56" \
        -display none -vga std $MONARG
    ;;
sshser)
    # SSH over COM1, bridged to a host TCP port. Same 386/586 CPU requirement as
    # the network SSH build. A stock `ssh` connects to the bridged port.
    echo "QEMU: COM1(SSH) -> tcp:127.0.0.1:$PORT  (ssh to this port)"
    exec qemu-system-i386 -machine accel=$QEMU_ACCEL -m 16 -cpu pentium2 -fda dosshd.img -boot a \
        -serial "tcp:127.0.0.1:$PORT,server,nowait" \
        -display none -vga std $MONARG
    ;;
*)
    echo "QEMU: COM1 -> tcp:127.0.0.1:$PORT  (connect with telnet/nc)"
    exec qemu-system-i386 -machine accel=$QEMU_ACCEL -m 16 -fda dosshd.img -boot a \
        -serial "tcp:127.0.0.1:$PORT,server,nowait" \
        -display none -vga std $MONARG
    ;;
esac
