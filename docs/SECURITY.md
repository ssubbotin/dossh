# Security

DOSSH is a plaintext telnet console with **no built-in authentication or
encryption yet**. Treat the wire as fully readable: anyone who can reach the port
sees the screen and every keystroke. That is fine on a trusted, isolated LAN; for
anything beyond that, put it behind a tunnel (encryption) and restrict who can
reach the port (a password gate is planned — see the roadmap).

Full SSH/TLS crypto is impractical to build *inside* a 16-bit real-mode TSR — not
because of CPU or memory on a modern box, but because implementing the SSH
protocol plus a 16-bit crypto library that interoperates byte-exactly with
OpenSSH is an enormous, security-critical surface that would dwarf the rest of
DOSSH (see [DESIGN.md](DESIGN.md) §14). The right move is to terminate encryption
on a capable machine that already has audited crypto, and forward plaintext only
the last hop, on the trusted LAN.

## Encrypt it with a tunnel

### Option A — SSH port-forward (simplest, recommended)

From your workstation, forward the DOS box's telnet port through any SSH-capable
host on the same LAN as the box (a jump box, a Raspberry Pi, the VPN gateway):

```sh
# terminal 1: open the encrypted tunnel (stays running)
ssh -N -L 2323:<dos-box-ip>:23 user@<lan-ssh-host>

# terminal 2: connect through it
printf '\e[8;25;80t'      # size to 25 rows x 80 cols
telnet 127.0.0.1 2323
```

Everything from your workstation to `<lan-ssh-host>` is encrypted by SSH; only the
final `<lan-ssh-host>` → `<dos-box>` hop is plaintext, and that stays inside the
trusted LAN.

### Option B — VPN

If the DOS box's LAN is already behind a VPN (WireGuard/OpenVPN), the VPN
encrypts the whole path — just connect over the VPN with plain
`telnet <dos-box-ip>`. This is the field setup.

### Option C — stunnel (TLS)

Run [`stunnel`](https://www.stunnel.org/) on a LAN host to wrap the telnet port in
TLS, and point a TLS client (or a second stunnel on your side) at it. More setup
than A/B; use it if you specifically need TLS.

## Authentication

Planned: a password gate shown before the console is granted. Until it lands,
restrict reachability (firewall / VPN-only). A password sent over an encrypted
tunnel (A/B/C above) is the intended posture — never over bare telnet on an
untrusted network.

## What DOSSH does *not* do

- No SSH/TLS on the DOS side (tunnel instead — above).
- No per-client isolation of secrets; a connected client drives the whole box.
- The `/U` uninstall and the smart-socket power-cycle are the recovery paths if a
  session or the box wedges.
