#!/usr/bin/env bash
# mkbootdisk.sh - build a bootable DOSSH network boot floppy.
#
# Assembles a DOS boot floppy that brings TCP/IP up over an NDIS2 network card
# and starts DOSSHD as a telnet console. One recipe covers MS-DOS and FreeDOS,
# a QEMU NIC or a real one. See ../docs/NETWORKING.md for the full story.
#
# Boot chain:  PROTMAN.DOS + <NIC>.DOS + DIS_PKT.DOS   (CONFIG.SYS/FDCONFIG.SYS)
#           -> NETBIND.COM  binds them into a packet driver at INT 0x60
#           -> DOSSHD.EXE /NET <ip> <port>             (AUTOEXEC.BAT/FDAUTO.BAT)
#
# The DOS networking stack (Protocol Manager, the NDIS2 MAC driver, the DIS_PKT
# shim, NETBIND) is vendor-supplied and not redistributable; you provide it via
# --stack and --nic-driver. Only DOSSHD and the generated config are ours.
#
# Requires: mtools (mcopy/mdir/mattrib).
set -euo pipefail

die() { echo "mkbootdisk: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: mkbootdisk.sh --os {msdos|freedos} --base BASE.img \
                     --nic-driver NIC.DOS --drivername NAME \
                     --ip A.B.C.D --out OUT.img [options]

Required:
  --os msdos|freedos    target DOS (a FreeDOS base MUST be 1.3+ / kernel 2043+)
  --base BASE.img       a bootable 1.44MB DOS floppy image to build on
  --nic-driver NIC.DOS  the NIC's NDIS2 MAC driver (e.g. RTGND.DOS, PCNTND.DOS)
  --drivername NAME     its NDIS DriverName, e.g. RTGND$  PCNTND$  MS2000$
  --ip A.B.C.D          static IP for DOSSHD
  --out OUT.img         output image path

Options:
  --port N              DOSSHD TCP port (default 23)
  --stack DIR           dir holding PROTMAN.DOS, PROTMAN.EXE, DIS_PKT.DOS,
                        NETBIND.COM (default ./drivers)
  --dosshd PATH         DOSSHD.EXE (default ../dosshd/DOSSHD.EXE)
  --medium              add "Medium = _auto" to the NIC section. RTGND needs it;
                        do NOT use it for PCNTND - PCNTND halts on it.
  --iobase 0xNNN        NE2000/ISA only (drivername MS2000$): I/O base, def 0x300
  --irq N               NE2000/ISA only: IRQ, def 3

Examples:
  # Real Realtek RTL8168h under FreeDOS 1.3:
  mkbootdisk.sh --os freedos --base FD13BOOT.img --nic-driver RTGND.DOS \
    --drivername 'RTGND$' --medium --ip 192.0.2.10 --out dossh-rtl8168.img

  # AMD PCnet in QEMU (recommended test bed):
  mkbootdisk.sh --os msdos --base msdos622.img --nic-driver PCNTND.DOS \
    --drivername 'PCNTND$' --ip 10.0.2.15 --out dossh-qemu.img
EOF
}

# ---- defaults ----
OS= BASE= NIC= DRV= IP= OUT= PORT=23 STACK=./drivers DOSSHD=../dosshd/DOSSHD.EXE
MEDIUM=0 IOBASE=0x300 IRQ=3

# ---- parse ----
while [ $# -gt 0 ]; do
  case "$1" in
    --os)          OS=$2; shift 2 ;;
    --base)        BASE=$2; shift 2 ;;
    --nic-driver)  NIC=$2; shift 2 ;;
    --drivername)  DRV=$2; shift 2 ;;
    --ip)          IP=$2; shift 2 ;;
    --out)         OUT=$2; shift 2 ;;
    --port)        PORT=$2; shift 2 ;;
    --stack)       STACK=$2; shift 2 ;;
    --dosshd)      DOSSHD=$2; shift 2 ;;
    --medium)      MEDIUM=1; shift ;;
    --iobase)      IOBASE=$2; shift 2 ;;
    --irq)         IRQ=$2; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (see --help)" ;;
  esac
done

# ---- validate ----
command -v mcopy >/dev/null 2>&1 || die "mtools not found (install 'mtools')"
[ -n "$OS" ] && [ -n "$BASE" ] && [ -n "$NIC" ] && [ -n "$DRV" ] && [ -n "$IP" ] && [ -n "$OUT" ] \
  || { usage; die "missing a required option"; }
case "$OS" in msdos|freedos) ;; *) die "--os must be msdos or freedos" ;; esac
echo "$IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die "--ip must be a dotted quad"
[ -f "$BASE" ] || die "base image not found: $BASE"
[ -f "$NIC" ]  || die "NIC driver not found: $NIC"
[ -f "$DOSSHD" ] || die "DOSSHD.EXE not found: $DOSSHD (build it, or pass --dosshd)"
[ -d "$STACK" ] || die "stack dir not found: $STACK"

# locate the four vendor stack files case-insensitively within --stack
resolve() {
  local want=$1 f
  for f in "$STACK"/*; do
    [ -e "$f" ] || continue
    if [ "$(basename "$f" | tr '[:lower:]' '[:upper:]')" = "$want" ]; then echo "$f"; return 0; fi
  done
  return 1
}
missing=
PROTMAN=$(resolve PROTMAN.DOS) || missing="$missing PROTMAN.DOS"
PROTEXE=$(resolve PROTMAN.EXE) || missing="$missing PROTMAN.EXE"
DISPKT=$(resolve DIS_PKT.DOS)  || missing="$missing DIS_PKT.DOS"
NETBIND=$(resolve NETBIND.COM) || missing="$missing NETBIND.COM"
if [ -n "$missing" ]; then
  echo "mkbootdisk: missing from --stack ($STACK):$missing" >&2
  case "$missing" in
    *PROTMAN.EXE*) echo "  NOTE: PROTMAN.EXE is required even though nothing runs it directly -" >&2
                   echo "        without it NETBIND fails with 'Error 45 Unable to bind'." >&2 ;;
  esac
  exit 1
fi

NICBASE=$(basename "$NIC" | tr '[:lower:]' '[:upper:]')   # e.g. RTGND.DOS
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
crlf() { sed 's/$/\r/'; }   # DOS line endings

# ---- PROTOCOL.INI ----
{
  echo "[protman]"
  echo "   DriverName = PROTMAN\$"
  echo "[NIC_NIF]"
  echo "   DriverName = $DRV"
  [ "$MEDIUM" = 1 ] && echo "   Medium     = _auto"
  if [ "$DRV" = 'MS2000$' ]; then
    echo "   IOBASE     = $IOBASE"
    echo "   INTERRUPT  = $IRQ"
  fi
  echo "[PKTDRV]"
  echo "   DriverName = PKTDRV\$"
  echo "   bindings   = NIC_NIF"
  echo "   intvec     = 0x60"
} | crlf > "$WORK/PROTOCOL.INI"

# ---- config + startup, per OS ----
cp -f "$BASE" "$OUT"
if [ "$OS" = msdos ]; then
  { echo "DEVICE=A:\\PROTMAN.DOS /I:A:\\"
    echo "DEVICE=A:\\$NICBASE"
    echo "DEVICE=A:\\DIS_PKT.DOS"; } | crlf > "$WORK/CONFIG.SYS"
  { echo "@ECHO OFF"
    echo "A:\\NETBIND.COM"
    echo "A:\\DOSSHD.EXE /NET $IP $PORT"; } | crlf > "$WORK/AUTOEXEC.BAT"
  mcopy -i "$OUT" -o "$WORK/CONFIG.SYS" "$WORK/AUTOEXEC.BAT" ::
else
  # FreeDOS 1.3+ boot floppies keep COMMAND.COM in \FREEDOS\BIN and run
  # \FDAUTO.BAT via the SHELL= line - preserve that line, just repoint /P=.
  # A FreeDOS FDCONFIG.SYS SHELL line may carry a menu-block prefix ("!" for all
  # blocks, "N?" / "123456?" for specific ones) - strip everything before SHELL=.
  shell_line=$(mcopy -n -i "$BASE" ::FDCONFIG.SYS - 2>/dev/null | tr -d '\r' \
               | grep -im1 'SHELL=' | sed -E 's/^.*(SHELL=)/\1/I') || true
  if [ -n "$shell_line" ]; then
    shell_line=$(printf '%s' "$shell_line" | sed -E 's#/P=[^ ]*#/P=\\FDAUTO.BAT#I')
    printf '%s' "$shell_line" | grep -qi '/P=' || shell_line="$shell_line /P=\\FDAUTO.BAT"
  else
    echo "mkbootdisk: warning: base FDCONFIG.SYS has no SHELL= line; using default." >&2
    shell_line='SHELL=\FREEDOS\BIN\COMMAND.COM \FREEDOS\BIN /E:2048 /P=\FDAUTO.BAT'
  fi
  { echo "LASTDRIVE=Z"
    echo "BUFFERS=20"
    echo "FILES=40"
    echo "DEVICE=A:\\PROTMAN.DOS /I:A:\\"
    echo "DEVICE=A:\\$NICBASE"
    echo "DEVICE=A:\\DIS_PKT.DOS"
    echo "$shell_line"; } | crlf > "$WORK/FDCONFIG.SYS"
  { echo "@ECHO OFF"
    echo "A:\\NETBIND.COM"
    echo "A:\\DOSSHD.EXE /NET $IP $PORT"; } | crlf > "$WORK/FDAUTO.BAT"
  mcopy -i "$OUT" -o "$WORK/FDCONFIG.SYS" ::FDCONFIG.SYS
  mcopy -i "$OUT" -o "$WORK/FDAUTO.BAT" ::FDAUTO.BAT
fi

# ---- files onto the image ----
mcopy -i "$OUT" -o "$WORK/PROTOCOL.INI" ::PROTOCOL.INI
mcopy -i "$OUT" -o "$PROTMAN" ::PROTMAN.DOS
mcopy -i "$OUT" -o "$PROTEXE" ::PROTMAN.EXE
mcopy -i "$OUT" -o "$DISPKT"  ::DIS_PKT.DOS
mcopy -i "$OUT" -o "$NETBIND" ::NETBIND.COM
mcopy -i "$OUT" -o "$NIC"     "::$NICBASE"
mcopy -i "$OUT" -o "$DOSSHD"  ::DOSSHD.EXE

echo "Built $OUT  ($OS, DriverName $DRV, DOSSHD /NET $IP $PORT)"
echo
echo "Test in QEMU (AMD PCnet - not ne2k, which truncates TX under QEMU):"
echo "  qemu-system-i386 -m 16 -fda $OUT -boot a \\"
echo "    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2323-:$PORT -device pcnet,netdev=n0"
echo "  telnet localhost 2323"
