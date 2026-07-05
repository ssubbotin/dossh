/*
 * sshd_native.c - a tiny native TCP server that drives the DOSSH SSH transport
 * (dosshd/ssh.c) against a real OpenSSH client, for interop testing on Linux.
 *
 * It is NOT the DOS build: it links the very same ssh.c + crypto + rng the DOS
 * target uses, but wrapped in a Berkeley socket loop instead of the resident
 * tick. Per connection it feeds socket bytes to ssh_input() and writes
 * ssh_output() back, logging state transitions and, on success, the decrypted
 * service name from the client's first post-NEWKEYS packet.
 *
 *   usage: sshd_native <port>
 *
 * Exit 0 iff the transport completed and SSH_MSG_SERVICE_REQUEST was decrypted.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "../dosshd/ssh.h"
#include "../dosshd/crypto/crypto.h"
#include "../dosshd/crypto/rng.h"

static const char *st_name(int s)
{
	switch (s) {
	case SSH_ST_VERSION:                 return "VERSION";
	case SSH_ST_EXPECT_KEXINIT:          return "EXPECT_KEXINIT";
	case SSH_ST_EXPECT_ECDH_INIT:        return "EXPECT_ECDH_INIT";
	case SSH_ST_EXPECT_CLIENT_NEWKEYS:   return "EXPECT_CLIENT_NEWKEYS";
	case SSH_ST_EXPECT_SERVICE_REQUEST:  return "EXPECT_SERVICE_REQUEST";
	case SSH_ST_DONE:                    return "DONE";
	case SSH_ST_ERROR:                   return "ERROR";
	default:                             return "?";
	}
}

static void drain_output(ssh_conn *c, int fd)
{
	uint8_t buf[1024];
	unsigned n;
	while ((n = ssh_output(c, buf, sizeof(buf))) > 0) {
		unsigned off = 0;
		while (off < n) {
			ssize_t w = write(fd, buf + off, n - off);
			if (w <= 0) return;
			off += (unsigned)w;
		}
	}
}

int main(int argc, char **argv)
{
	int port, ls, cs, one = 1, last_state, kex_logged = 0;
	struct sockaddr_in sa;
	uint8_t hostkey_sk[64], hostkey_pk[32], seed[32];
	uint8_t rseed[32];
	ssh_conn c;
	FILE *ur;

	if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
	port = atoi(argv[1]);

	/* Seed the CSPRNG from the OS so server ephemerals are real (this is the
	 * native interop harness, never the DOS resident). */
	ur = fopen("/dev/urandom", "rb");
	if (ur) { if (fread(rseed, 1, sizeof(rseed), ur) != sizeof(rseed)) {} fclose(ur); }
	else    { memset(rseed, 0x5a, sizeof(rseed)); }
	rng_seed_for_test(rseed, sizeof(rseed));

	/* Stable test ed25519 host key from a fixed seed (UserKnownHostsFile is
	 * /dev/null in the e2e, so pinning does not matter, but keep it stable). */
	memset(seed, 0, sizeof(seed));
	memcpy(seed, "DOSSH-test-ed25519-hostkey-seed!", 32);
	dossh_ed25519_key_pair(hostkey_sk, hostkey_pk, seed);
	{
		int i;
		printf("host key ssh-ed25519 pub:");
		for (i = 0; i < 32; i++) printf("%02x", hostkey_pk[i]);
		printf("\n");
	}

	ls = socket(AF_INET, SOCK_STREAM, 0);
	if (ls < 0) { perror("socket"); return 2; }
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons((unsigned short)port);
	if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 2; }
	if (listen(ls, 1) < 0) { perror("listen"); return 2; }
	printf("listening on 127.0.0.1:%d\n", port);
	fflush(stdout);

	cs = accept(ls, NULL, NULL);
	if (cs < 0) { perror("accept"); return 2; }
	{
		struct timeval tv; tv.tv_sec = 10; tv.tv_usec = 0;
		setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	ssh_reset(&c, hostkey_sk, hostkey_pk);
	last_state = c.state;
	printf("STATE: %s\n", ssh_state_name(&c));
	fflush(stdout);
	drain_output(&c, cs);

	for (;;) {
		uint8_t buf[1024];
		ssize_t r = read(cs, buf, sizeof(buf));
		if (r <= 0) { printf("client closed / read end (r=%ld)\n", (long)r); break; }

		if (ssh_input(&c, buf, (unsigned)r) < 0) {
			printf("SSH ERROR: %s\n", c.err_msg ? c.err_msg : "?");
			fflush(stdout);
			break;
		}
		drain_output(&c, cs);

		if (c.state != last_state) {
			printf("STATE: %s -> %s\n", st_name(last_state), st_name(c.state));
			last_state = c.state;
		}
		if (!kex_logged && c.keys_ready) {
			printf("client version: %s\n", c.cli_ver);
			printf("kex complete: curve25519-sha256 + ssh-ed25519; session keys derived\n");
			printf("SENT KEX_ECDH_REPLY + NEWKEYS (send side now encrypted)\n");
			kex_logged = 1;
			fflush(stdout);
		}
		if (ssh_done(&c)) {
			printf("DECRYPTED SERVICE_REQUEST: %s\n", c.svc_name);
			printf("transport complete; stopping (userauth is the next layer)\n");
			fflush(stdout);
			drain_output(&c, cs);      /* flush our SERVICE_ACCEPT */
			break;
		}
	}

	/* give the client a moment to read our final SERVICE_ACCEPT before FIN */
	{
		uint8_t junk[256];
		struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
		setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		while (read(cs, junk, sizeof(junk)) > 0) { /* drain client tail */ }
	}
	close(cs);
	close(ls);

	if (ssh_done(&c)) { printf("RESULT: PASS\n"); return 0; }
	printf("RESULT: FAIL (state=%s)\n", ssh_state_name(&c));
	return 1;
}
