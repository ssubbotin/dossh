# net/ — DOSSH network boot disks

`mkbootdisk.sh` builds a bootable DOS floppy that brings TCP/IP up over an NDIS2
network card and starts `DOSSHD` as a telnet console — for MS-DOS or FreeDOS, in
QEMU or on real hardware.

```sh
./mkbootdisk.sh --help
```

You supply the (non-redistributable) DOS networking stack — Protocol Manager,
the NIC's NDIS2 driver, the DIS_PKT shim, NETBIND — via `--stack` and
`--nic-driver`. Only `DOSSHD.EXE` and the generated config are part of this
project.

See [../docs/NETWORKING.md](../docs/NETWORKING.md) for where to get the drivers,
the full recipe, the deployment steps, and the gotchas.
