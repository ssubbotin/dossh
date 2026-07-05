/*
 * ssh.h - DOSSH SSH-2.0 server: transport (RFC 4253) + userauth (RFC 4252)
 *         + one session channel (RFC 4254).
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
 * chacha20-poly1305@openssh.com record layer and NEWKEYS; then password
 * userauth (RFC 4252) and a single "session" channel with pty-req / shell /
 * window-change (RFC 4254). Once the shell request is granted the channel is a
 * plain byte pipe: ssh_channel_getc pulls decrypted client keystrokes and
 * ssh_channel_putc / ssh_channel_flush push encrypted screen bytes, mirroring
 * the net_rx_getc / net_tx_putc / net_tx_flush shape the telnet path uses.
 *
 * Auth policy (mirrors telnet's "no /P = open"): if ssh_set_password() has NOT
 * been called (or is set empty), the server accepts the client's first auth
 * attempt of any method (open box). If a password IS configured, only the SSH
 * "password" method with a matching secret authenticates; "none"/"publickey"
 * and wrong passwords get SSH_MSG_USERAUTH_FAILURE listing "password", and
 * after a few failures the server sends SSH_MSG_DISCONNECT. Publickey is P2.
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

/* Channel-data plumbing. CIN is the decrypted-keystroke ring the client types
 * into (small: keystrokes, drained every tick); COUT stages screen bytes to be
 * framed as CHANNEL_DATA. A single CHANNEL_DATA payload must fit send_enc's
 * body buffer (payload <= ~247), so we flush in <= SSH_CHAN_CHUNK slices. */
#define SSH_CIN_SZ        256   /* inbound channel-data ring (client keystrokes) */
#define SSH_COUT_SZ       512   /* outbound channel-data staging buffer           */
#define SSH_CHAN_CHUNK    200   /* max data bytes per CHANNEL_DATA packet         */
#define SSH_LOCAL_WINDOW  32768 /* bytes we let the client send before adjusting  */
#define SSH_CHAN_MAXPKT   1024  /* max packet size we advertise for our channel   */
#define SSH_MAX_AUTH_TRIES  3   /* wrong-password attempts before DISCONNECT      */

/* State machine states (exposed so a test/harness can log transitions). The
 * transport half runs VERSION..EXPECT_SERVICE_REQUEST exactly as before; once
 * SERVICE_REQUEST(ssh-userauth) is decrypted it advances into AUTH, then
 * SESSION (channel up), rather than stopping. */
enum {
	SSH_ST_VERSION = 0,          /* awaiting the client's SSH- identification */
	SSH_ST_EXPECT_KEXINIT,       /* awaiting SSH_MSG_KEXINIT                   */
	SSH_ST_EXPECT_ECDH_INIT,     /* awaiting SSH_MSG_KEX_ECDH_INIT            */
	SSH_ST_EXPECT_CLIENT_NEWKEYS,/* awaiting the client's SSH_MSG_NEWKEYS     */
	SSH_ST_EXPECT_SERVICE_REQUEST,/* encrypted; awaiting SERVICE_REQUEST      */
	SSH_ST_AUTH,                 /* SERVICE_ACCEPT sent; running userauth      */
	SSH_ST_SESSION,              /* authenticated; channel open/data phase     */
	SSH_ST_CLOSED,               /* peer disconnected / channel closed cleanly */
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

	/* ---- userauth (RFC 4252) ---------------------------------------- */
	char         password[64];   /* configured secret; empty => open box       */
	int          have_password;  /* 1 once ssh_set_password gave a non-empty pw */
	int          authenticated;  /* 1 after SSH_MSG_USERAUTH_SUCCESS            */
	unsigned     auth_fails;     /* wrong/rejected attempts (retry budget)      */
	char         auth_user[64];  /* last requested user name (informational)    */

	/* ---- connection / session channel (RFC 4254) -------------------- */
	int          chan_open;      /* a "session" channel is open                */
	uint32_t     peer_chan;      /* client's channel id (recipient of our msgs) */
	uint32_t     local_chan;     /* our channel id                             */
	uint32_t     peer_window;    /* bytes we may still send to the client       */
	uint32_t     peer_maxpkt;    /* max CHANNEL_DATA the client will accept      */
	uint32_t     local_window;   /* bytes the client may still send us          */
	int          pty;            /* pty-req received                            */
	int          shell_ready;    /* "shell"/"exec" granted: channel is a pipe   */
	unsigned     term_cols;      /* terminal width  (SSH's NAWS equivalent)     */
	unsigned     term_rows;      /* terminal height                            */
	int          chan_eof;       /* client sent CHANNEL_EOF                      */
	int          chan_sent_eof;  /* we sent CHANNEL_EOF                          */
	int          chan_sent_close;/* we sent CHANNEL_CLOSE                        */
	int          chan_closed;    /* channel fully torn down                      */

	/* decrypted client keystrokes waiting for ssh_channel_getc (ring) */
	uint8_t      cin[SSH_CIN_SZ]; unsigned cin_head, cin_tail;
	/* screen bytes staged by ssh_channel_putc, framed by ssh_channel_flush */
	uint8_t      cout[SSH_COUT_SZ]; unsigned cout_len;
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

/* 1 once the transport is up and the client's SERVICE_REQUEST was decrypted.
 * (Latched; the machine keeps running through userauth and the channel.) */
int DOSSH_FAR ssh_done(ssh_conn *c);

/* 1 if a fatal error has been latched (state == SSH_ST_ERROR). */
int DOSSH_FAR ssh_failed(ssh_conn *c);

/* Stable name for the current state (for logging). */
const char * DOSSH_FAR ssh_state_name(ssh_conn *c);

/* ---- userauth ------------------------------------------------------- */

/* Configure the password checked by SSH "password" auth (mirrors
 * telnet_set_password). Call AFTER ssh_reset (which zeroes the struct). An
 * empty/NULL string leaves the box open: the first auth attempt is accepted. */
void DOSSH_FAR ssh_set_password(ssh_conn *c, const char *pw);

/* 1 once userauth has succeeded. */
int DOSSH_FAR ssh_authenticated(ssh_conn *c);

/* ---- session channel byte interface (mirrors net_rx/net_tx) --------- */

/* 1 when the session channel is open and its shell/exec request was granted -
 * i.e. the channel is a live byte pipe (the analogue of net_connected). */
int DOSSH_FAR ssh_channel_ready(ssh_conn *c);

/* Next decrypted client keystroke byte from CHANNEL_DATA, or -1 if none.
 * (Feed this to ansi_key_byte, exactly like net_rx_getc.) */
int DOSSH_FAR ssh_channel_getc(ssh_conn *c);

/* Stage one screen byte to be sent as encrypted CHANNEL_DATA. Returns 1 if
 * queued, 0 if the staging buffer is full (caller should push back and retry
 * next tick, like net_tx_putc). Call ssh_channel_flush() to frame+encrypt. */
int DOSSH_FAR ssh_channel_putc(ssh_conn *c, int byte);

/* Frame staged bytes into CHANNEL_DATA packet(s), honouring the client's flow-
 * control window and max packet size; leftover stays buffered when the window
 * is exhausted. Mirrors net_tx_flush. */
void DOSSH_FAR ssh_channel_flush(ssh_conn *c);

/* Report the client's terminal size from pty-req/window-change (defaults
 * 80x25 until the client tells us). This is SSH's NAWS equivalent. */
void DOSSH_FAR ssh_winsize(ssh_conn *c, int *cols, int *rows);

/* 1 if the client has signalled CHANNEL_EOF (no more keystrokes coming). */
int DOSSH_FAR ssh_channel_eof(ssh_conn *c);

/* Half/close the channel: flush pending data, send CHANNEL_EOF + CHANNEL_CLOSE. */
void DOSSH_FAR ssh_channel_close(ssh_conn *c);

/* 1 once the channel is fully closed (either side). */
int DOSSH_FAR ssh_channel_closed(ssh_conn *c);

#endif /* DOSSH_SSH_H */
