/*
 * sshd_native.c - a tiny native TCP server that drives the DOSSH SSH server
 * (dosshd/ssh.c) against a real OpenSSH client, for interop testing on Linux.
 *
 * It is NOT the DOS build: it links the very same ssh.c + crypto + rng the DOS
 * target uses, but wrapped in a Berkeley socket loop instead of the resident
 * tick. Per connection it feeds socket bytes to ssh_input() and writes
 * ssh_output() back, logging state transitions.
 *
 *   usage: sshd_native <port> [--shell] [--pass=<password>]
 *
 * Default (transport-only): completes the SSH transport and stops once the
 * client's first post-NEWKEYS SSH_MSG_SERVICE_REQUEST is decrypted; exit 0 iff
 * that happened. This is what test/e2e-ssh-transport.sh drives.
 *
 * --shell / --pass=<pw>: run the full stack - userauth (password if --pass is
 * given, otherwise the open box) and one session channel - then act as a
 * trivial interactive "shell": after the shell request is granted it sends a
 * banner + prompt via ssh_channel_putc and ECHOES every byte pulled from
 * ssh_channel_getc, proving both-direction channel data over the encrypted
 * transport. This is what test/e2e-ssh-shell.sh drives. Exit 0 iff a shell was
 * granted (i.e. auth succeeded and the channel came up).
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
	case SSH_ST_AUTH:                    return "AUTH";
	case SSH_ST_SESSION:                 return "SESSION";
	case SSH_ST_CLOSED:                  return "CLOSED";
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

/* queue a NUL-terminated string as channel data (screen bytes) */
static void chan_say(ssh_conn *c, const char *s)
{
	while (*s) ssh_channel_putc(c, (unsigned char)*s++);
}

int main(int argc, char **argv)
{
	int port, ls, cs, one = 1, last_state, kex_logged = 0;
	int shell_mode = 0, service_logged = 0, banner_sent = 0;
	const char *password = NULL;
	struct sockaddr_in sa;
	uint8_t hostkey_sk[64], hostkey_pk[32], seed[32];
	uint8_t rseed[32];
	ssh_conn c;
	FILE *ur;
	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <port> [--shell] [--pass=<pw>]\n", argv[0]);
		return 2;
	}
	port = atoi(argv[1]);
	for (i = 2; i < argc; i++) {
		if (strncmp(argv[i], "--pass=", 7) == 0) { password = argv[i] + 7; shell_mode = 1; }
		else if (strcmp(argv[i], "--shell") == 0) shell_mode = 1;
	}

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
	if (password) {
		ssh_set_password(&c, password);
		printf("password auth enabled\n");
	} else if (shell_mode) {
		printf("open box (no password: first auth attempt admitted)\n");
	}
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
		if (ssh_done(&c) && !service_logged) {
			printf("DECRYPTED SERVICE_REQUEST: %s\n", c.svc_name);
			service_logged = 1;
			fflush(stdout);
			if (!shell_mode) {
				printf("transport complete; stopping (transport-only mode)\n");
				fflush(stdout);
				drain_output(&c, cs);      /* flush our SERVICE_ACCEPT */
				break;
			}
		}

		if (shell_mode) {
			if (ssh_authenticated(&c) && !banner_sent && !ssh_channel_ready(&c)) {
				/* one-time note the moment auth passes */
				static int auth_logged = 0;
				if (!auth_logged) {
					printf("USERAUTH SUCCESS (user=%s)\n", c.auth_user);
					auth_logged = 1;
					fflush(stdout);
				}
			}
			if (ssh_channel_ready(&c) && !banner_sent) {
				int cols = 0, rows = 0;
				ssh_winsize(&c, &cols, &rows);
				printf("SHELL READY (pty=%d, %dx%d)\n", c.pty, cols, rows);
				fflush(stdout);
				chan_say(&c, "DOSSH interactive shell ready\r\n$ ");
				banner_sent = 1;
			}
			if (banner_sent) {
				int b;
				while ((b = ssh_channel_getc(&c)) >= 0) {
					ssh_channel_putc(&c, b);           /* echo it back      */
					if (b == '\r') ssh_channel_putc(&c, '\n'); /* CR -> CRLF */
				}
				ssh_channel_flush(&c);
				/* client done typing: echo drained, close so ssh exits cleanly */
				if (ssh_channel_eof(&c) && !ssh_channel_closed(&c))
					ssh_channel_close(&c);
			}
		}

		drain_output(&c, cs);
		if (c.state == SSH_ST_CLOSED) { printf("connection closed\n"); break; }
	}

	/* give the client a moment to read our final bytes before FIN */
	{
		uint8_t junk[256];
		struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
		setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		while (read(cs, junk, sizeof(junk)) > 0) { /* drain client tail */ }
	}
	close(cs);
	close(ls);

	if (shell_mode) {
		if (banner_sent) { printf("RESULT: PASS\n"); return 0; }
		printf("RESULT: FAIL (no shell; auth_fails=%u, state=%s)\n",
		       c.auth_fails, ssh_state_name(&c));
		return 1;
	}
	if (ssh_done(&c)) { printf("RESULT: PASS\n"); return 0; }
	printf("RESULT: FAIL (state=%s)\n", ssh_state_name(&c));
	return 1;
}
