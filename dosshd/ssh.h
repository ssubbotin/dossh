/*
 * ssh.h - DOSSH SSH-2.0 transport layer (RFC 4253), transport-only.
 *
 * A transport-agnostic, byte-fed state machine (design arch B): it never
 * blocks and holds no I/O of its own. The caller feeds it inbound bytes with
 * ssh_input() and drains outbound bytes with ssh_output(); everything else is
 * in the ssh_conn struct, so it drops straight into the resident tick later
 * (where net_rx_getc/net_tx_putc are the byte stream) and supports one
 * instance per client slot with no shared mutable state (a single transient
 * computation scratch is reused non-reentrantly within one call, matching the
 * cooperative tick).
 *
 * Implemented: version exchange, KEXINIT negotiation offering exactly
 * curve25519-sha256(+@libssh.org) / ssh-ed25519 / chacha20-poly1305@openssh.com,
 * curve25519 key exchange (RFC 8731), key derivation (RFC 4253 sec 7.2), the
 * chacha20-poly1305@openssh.com record layer, and NEWKEYS. It stops once the
 * transport is encrypted and the client's first post-NEWKEYS packet (a real
 * ssh sends SSH_MSG_SERVICE_REQUEST "ssh-userauth") has been decrypted. No
 * userauth, no channels - those are the next layer.
 *
 * NOTE: no libc dependency beyond memcpy/memset/memmove/memcmp/strlen. Crypto
 * comes through the __far crypto.h / rng.h primitives, so this compiles both
 * natively (interop test) and for the 386 real-mode DOS target (-mm -3).
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_SSH_H
#define DOSSH_SSH_H

#include <stdint.h>
#include "crypto.h"        /* DOSSH_FAR */

/* Buffer sizes (all live in the ssh_conn struct, i.e. DGROUP on DOS). A single
 * binary packet must fit ib/ob; the client KEXINIT is the largest (~1.1 KB). */
#define SSH_IB_SZ   2048   /* inbound packet-accumulation buffer            */
#define SSH_OB_SZ   2048   /* outbound drain buffer                          */
#define SSH_IC_SZ   2048   /* stored client KEXINIT payload  (I_C)          */
#define SSH_IS_SZ    512   /* stored server KEXINIT payload  (I_S)          */

/* Handshake states (exposed so a test/harness can log transitions). */
enum {
	SSH_ST_VERSION = 0,          /* awaiting the client's SSH- identification */
	SSH_ST_EXPECT_KEXINIT,       /* awaiting SSH_MSG_KEXINIT                   */
	SSH_ST_EXPECT_ECDH_INIT,     /* awaiting SSH_MSG_KEX_ECDH_INIT            */
	SSH_ST_EXPECT_CLIENT_NEWKEYS,/* awaiting the client's SSH_MSG_NEWKEYS     */
	SSH_ST_EXPECT_SERVICE_REQUEST,/* encrypted; awaiting SERVICE_REQUEST      */
	SSH_ST_DONE,                 /* transport up, service request decrypted   */
	SSH_ST_ERROR                 /* protocol/crypto failure (see err_msg)     */
};

typedef struct ssh_conn {
	int          state;
	int          err;            /* nonzero once a fatal error is latched      */
	const char  *err_msg;        /* human-readable reason (native only)        */
	int          done;           /* 1 once SERVICE_REQUEST has been decrypted  */

	/* ed25519 host key (expanded secret seed||pub, and the public key) */
	uint8_t      hostkey_sk[64];
	uint8_t      hostkey_pk[32];

	/* peer identification string, CR/LF stripped (V_C) */
	char         cli_ver[256];
	unsigned     cli_ver_len;

	/* inbound accumulation + outbound drain */
	uint8_t      ib[SSH_IB_SZ]; unsigned ib_len;
	uint8_t      ob[SSH_OB_SZ]; unsigned ob_len;

	/* verbatim KEXINIT payloads for the exchange hash */
	uint8_t      i_c[SSH_IC_SZ]; unsigned i_c_len;
	uint8_t      i_s[SSH_IS_SZ]; unsigned i_s_len;

	/* key-exchange working values */
	uint8_t      q_c[32];        /* client ephemeral public                    */
	uint8_t      q_s[32];        /* server ephemeral public                    */
	uint8_t      eph_sk[32];     /* server ephemeral secret                    */
	uint8_t      k_raw[32];      /* raw X25519 shared secret                   */
	uint8_t      kmpint[40];     /* shared secret encoded as an mpint (K)      */
	unsigned     kmpint_len;
	uint8_t      ks_blob[64];    /* host-key blob K_S                          */
	unsigned     ks_len;

	uint8_t      H[32];          /* exchange hash                              */
	uint8_t      session_id[32]; /* = H of the first kex                       */
	int          have_session_id;

	/* chacha20-poly1305@openssh.com key material (64 bytes each direction):
	 * bytes 0..31 = main key (poly1305 key + payload), 32..63 = header key. */
	uint8_t      ek_c2s[64];     /* client->server (we decrypt with this)      */
	uint8_t      ek_s2c[64];     /* server->client (we encrypt with this)      */
	int          keys_ready;

	int          recv_encrypted; /* set after the client's NEWKEYS             */
	int          send_encrypted; /* set after we send NEWKEYS                  */
	uint32_t     send_seq;       /* outbound binary-packet sequence number     */
	uint32_t     recv_seq;       /* inbound  binary-packet sequence number     */

	int          cli_first_follows; /* client KEXINIT first_kex_packet_follows */
	int          discard_next;   /* drop the next packet (wrong kex guess)     */

	char         svc_name[64];   /* decoded SERVICE_REQUEST service name       */
} ssh_conn;

/* Reset a connection and queue our version string + KEXINIT into the output
 * buffer. hostkey_sk/pk are the ed25519 host key (from dossh_ed25519_key_pair).
 * The caller should drain ssh_output() immediately after this call. */
void DOSSH_FAR ssh_reset(ssh_conn *c, const uint8_t hostkey_sk[64],
                         const uint8_t hostkey_pk[32]);

/* Feed n inbound bytes; advances the state machine as far as the data allows,
 * queuing any responses into the output buffer. Returns 0 on success (may be
 * incomplete, awaiting more bytes) or -1 once a fatal error is latched. */
int DOSSH_FAR ssh_input(ssh_conn *c, const uint8_t *data, unsigned n);

/* Copy up to max pending outbound bytes into buf, removing them from the queue.
 * Returns the number copied (0 when the queue is empty). Call in a loop. */
unsigned DOSSH_FAR ssh_output(ssh_conn *c, uint8_t *buf, unsigned max);

/* 1 once the transport is up and the client's SERVICE_REQUEST was decrypted. */
int DOSSH_FAR ssh_done(ssh_conn *c);

/* 1 if a fatal error has been latched (state == SSH_ST_ERROR). */
int DOSSH_FAR ssh_failed(ssh_conn *c);

/* Stable name for the current state (for logging). */
const char * DOSSH_FAR ssh_state_name(ssh_conn *c);

#endif /* DOSSH_SSH_H */
