# DOSSH networking & deployment

`DOSSHD` carries its session over TCP using a **DOS packet driver** at software
interrupt `0x60`. This guide shows how to give a DOS machine one — on a real
network card or in an emulator — and boot straight into a working DOSSH console.

It is verified end to end on **MS-DOS 6.22** and **FreeDOS 1.3**, both in **QEMU**
(AMD PCnet) and on **real hardware** (an onboard Realtek RTL8168h), driven
interactively over `telnet`.

## The problem, and the stack that solves it

Old NICs shipped a Crynwr *packet driver* — a small TSR that presents a simple
API at an interrupt vector. Modern cards (e.g. Realtek RTL8168/8111) never got
one; they only have an **NDIS2** driver. The bridge is a four-piece stack:

```
  CONFIG.SYS / FDCONFIG.SYS          AUTOEXEC.BAT / FDAUTO.BAT
  ---------------------------        -------------------------
  PROTMAN.DOS   (Protocol Mgr)  ┐
  <NIC>.DOS     (NDIS2 MAC)     ├─►  NETBIND.COM  ──► packet driver @ INT 0x60
  DIS_PKT.DOS   (NDIS2→pktdrv)  ┘                     └─►  DOSSHD.EXE /NET <ip>
```

`NETBIND` binds the loaded modules; `DIS_PKT` then exposes them as a packet
driver that `DOSSHD` (and mTCP tools) can use.

## Quick start: `net/mkbootdisk.sh`

The script wires all of this up for you from a base DOS floppy plus the drivers
you supply:

```sh
# AMD PCnet in QEMU (the recommended test bed):
net/mkbootdisk.sh --os msdos --base msdos622.img \
  --nic-driver PCNTND.DOS --drivername 'PCNTND$' \
  --ip 10.0.2.15 --out dossh-qemu.img --stack ./drivers

# Real Realtek RTL8168h under FreeDOS 1.3:
net/mkbootdisk.sh --os freedos --base FD13BOOT.img \
  --nic-driver RTGND.DOS --drivername 'RTGND$' --medium \
  --ip 192.0.2.10 --out dossh-rtl8168.img --stack ./drivers
```

`--stack` is a directory holding `PROTMAN.DOS`, `PROTMAN.EXE`, `DIS_PKT.DOS`,
`NETBIND.COM`. Run `net/mkbootdisk.sh --help` for all options. It needs
`mtools`.

## Files you must supply

These are not redistributable and are **not** in this repo. Get them once:

| Files | Where | Notes |
| --- | --- | --- |
| `PROTMAN.DOS`, `PROTMAN.EXE`, `NETBIND.COM` | MS Network Client 3.0 (archive.org item `MSCLIENT30`, disks `DSK3-1.EXE`/`DSK3-2.EXE`) | the Protocol Manager + binder |
| `DIS_PKT.DOS` v1.11 | `packetdriversdos.net/ZIP/dis_pkt11.zip` | the NDIS2→packet-driver shim |
| `RTGND.DOS` v1.54 (RTL8168/8111) | `packetdriversdos.net/ZIP/RTGBND2.1.54_EXE68.ZIP` | DriverName `RTGND$` |
| `PCNTND.DOS` (AMD PCnet) | `packetdriversdos.net` `amdnic_2.zip`, path `PCNFS/PCNTND.DOS` | DriverName `PCNTND$` — ideal for QEMU |
| `NE2000.DOS` | MS Network Client 3.0 | DriverName `MS2000$` |

## Gotcha #1 — `PROTMAN.EXE` must be present

`NETBIND.COM` requires `PROTMAN.EXE` to exist on the disk, even though nothing
loads or runs it directly. If it is missing, `NETBIND` fails with **`Error 45
Unable to bind`** and no packet driver appears. This one missing file is the
single most common cause of a silent failure. Always include it.

## `PROTOCOL.INI`

```ini
[protman]
   DriverName = PROTMAN$
[NIC_NIF]
   DriverName = RTGND$        ; or PCNTND$ / MS2000$
   Medium     = _auto         ; RTGND only — see below
[PKTDRV]
   DriverName = PKTDRV$
   bindings   = NIC_NIF
   intvec     = 0x60
```

**Gotcha #2:** `Medium = _auto` is an *RTGND* parameter. Do **not** put it in a
`PCNTND` (PCnet) section — PCNTND rejects it with `PCNTND$-DOS-#MEDIUM - Unknown
parameter` and halts CONFIG.SYS. For NE2000 (`MS2000$`) drop `Medium` and add
`IOBASE = 0x300` / `INTERRUPT = 3` instead.

## MS-DOS 6.22

`CONFIG.SYS`:

```
DEVICE=A:\PROTMAN.DOS /I:A:\
DEVICE=A:\<NIC>.DOS
DEVICE=A:\DIS_PKT.DOS
```

`AUTOEXEC.BAT`:

```
@ECHO OFF
A:\NETBIND.COM
A:\DOSSHD.EXE /NET <ip> 23
```

Order matters: PROTMAN, then the NIC driver, then DIS_PKT. `NETBIND` runs from
`AUTOEXEC` (never as a device driver).

## FreeDOS — use 1.3 or newer

**Gotcha #3 (critical):** FreeDOS **1.2** ships kernel build **2041** (2016),
which faults this class of gigabit NDIS2 driver — the driver loads but faults on
the first real network operation (the same signature as Intel's `e1000.dos`
under FreeDOS but not under MS-DOS). FreeDOS **1.3 and 1.4** ship kernel build
**2043**, which fixes it. Use the FreeDOS 1.3 (or 1.4) *Floppy Edition* boot
floppy as your base.

**Gotcha #4:** the 1.3/1.4 boot floppy keeps `COMMAND.COM` in `\FREEDOS\BIN\` and
runs `\FDAUTO.BAT` as its startup, wired through the `SHELL=` line in
`FDCONFIG.SYS`. If you replace `FDCONFIG.SYS` with a minimal one that drops
`SHELL=`, you get `Bad or missing Command Interpreter`. Keep it.

`FDCONFIG.SYS`:

```
LASTDRIVE=Z
BUFFERS=20
FILES=40
DEVICE=A:\PROTMAN.DOS /I:A:\
DEVICE=A:\<NIC>.DOS
DEVICE=A:\DIS_PKT.DOS
SHELL=\FREEDOS\BIN\COMMAND.COM \FREEDOS\BIN /E:2048 /P=\FDAUTO.BAT
```

`\FDAUTO.BAT` (the FreeDOS startup, at the root — not `AUTOEXEC.BAT`):

```
@ECHO OFF
A:\NETBIND.COM
A:\DOSSHD.EXE /NET <ip> 23
```

No DOS-version spoof and no memory manager are needed. Avoid `EMM386`/`JEMMEX`
(they can stomp a gigabit NIC's memory window) and load the drivers low
(`DEVICE=`, not `DEVICEHIGH`).

## Test in QEMU first

Use **AMD PCnet** — a bus-master NIC like the RTL8168, which QEMU emulates
cleanly. Do **not** use QEMU's NE2000 (`ne2k_isa`): under QEMU the MS NE2000
driver truncates TX to ~60 bytes, which silently breaks everything downstream.

```sh
qemu-system-i386 -m 16 -fda dossh-qemu.img -boot a \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2323-:23 -device pcnet,netdev=n0
telnet localhost 2323
```

You should see the live DOS screen and be able to type into it. Under QEMU
SLIRP, DOSSHD's IP is typically `10.0.2.15`.

## Deploy to a real headless box (GRUB + memdisk)

A machine that normally boots Linux can boot the DOSSH floppy **once, remotely,
without touching hardware**, using syslinux `memdisk` as a one-shot GRUB entry:

1. Copy `memdisk` (from the `syslinux` package) to `/boot/memdisk`, and your
   image to `/boot/dossh.img`.
2. Add a GRUB entry (e.g. `/etc/grub.d/40_custom`, then `update-grub`):

   ```
   menuentry "DOSSH one-shot" {
       linux16 /boot/memdisk
       initrd16 /boot/dossh.img
   }
   ```
3. Arm it for a single boot and reboot:

   ```sh
   sudo grub-reboot "DOSSH one-shot" && sudo reboot
   ```

   `grub-reboot` sets `next_entry` for exactly one boot, so if DOS ever hangs a
   power-cycle brings the machine straight back to Linux — safe for a remote box.
4. Give DOSSHD a static IP for the LAN (`DOSSHD.EXE /NET <ip> 23`). DOSSHD
   replies using the source MAC of the frame that reached it, so a client on
   another subnet, reaching it through a gateway, works fine.

Use a 1.44 MB floppy image (standard geometry) — `memdisk` boots those reliably.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Error 45 Unable to bind` | `PROTMAN.EXE` not on the disk | include it (gotcha #1) |
| `#MEDIUM - Unknown parameter` / `Press any key` | `Medium=` in a non-RTGND section | remove it (gotcha #2) |
| `Bad or missing Command Interpreter` | dropped the FreeDOS `SHELL=` line | keep it (gotcha #4) |
| FreeDOS boots but never networks on a gigabit NIC | FreeDOS 1.2 kernel 2041 | use FreeDOS 1.3+ (gotcha #3) |
| Console/DHCP silently gets nothing in QEMU | `ne2k_isa` TX truncation | use `-device pcnet` |
| `DOSSHD: no packet driver found` | `NETBIND` did not bind | check gotchas #1 and #2 |
