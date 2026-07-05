/*
 * sshlink.c - DOS link/smoke proof for the SSH transport (dosshd/ssh.c).
 *
 * ssh.c is the portable SSH-2.0 transport state machine; the functional interop
 * proof runs natively (test/e2e-ssh-transport.sh against a real OpenSSH client).
 * This tiny real-mode program exists only to prove ssh.c COMPILES -mm -3 and
 * LINKS clean against the -3 crypto + rng into an actual DOS EXE - the same
 * mixed medium-model image a future SSH-enabled DOSSHD would use. It resets a
 * connection with a throwaway host key and checks the queued server ID string.
 *
 * Requires a 586+ (rng.c uses RDTSC). Build: see dosshd/build.sh.
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>

#include "ssh.h"
#include "crypto.h"

static ssh_conn c;    /* ~7 KB; a single instance fits medium-model DGROUP */

int main(void)
{
	unsigned char sk[64], pk[32], seed[32], out[64];
	unsigned n, i;
	int ok;

	for (i = 0; i < 32; i++) seed[i] = (unsigned char)(i + 1);
	dossh_ed25519_key_pair(sk, pk, seed);

	ssh_reset(&c, sk, pk);
	n = ssh_output(&c, out, sizeof(out));

	printf("ssh_reset queued %u bytes; id=", n);
	for (i = 0; i < 19 && i < n; i++) putchar(out[i]);
	putchar('\n');

	/* the queue must start with our identification string */
	ok = !ssh_failed(&c) && n >= 19 &&
	     out[0] == 'S' && out[1] == 'S' && out[2] == 'H' && out[3] == '-';
	puts(ok ? "SSH link/smoke OK" : "SSH LINK TEST FAIL");
	return ok ? 0 : 1;
}
