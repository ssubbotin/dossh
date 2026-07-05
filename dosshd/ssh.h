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
 * Auth policy (mirrors telnet's "no /P = open"): if neither ssh_set_password()
 * nor ssh_set_authorized_keys() has been called (open box), the server accepts
 * the client's first auth attempt of any method. Once a password and/or
 * authorized keys are configured, the box is gated: "publickey" (RFC 4252 sec 7,
 * ssh-ed25519 only) authenticates a client whose key is in the authorized set
 * and whose signature verifies over the session-bound data - no secret ever
 * crosses the wire; "password" authenticates a matching secret. Failures get
 * SSH_MSG_USERAUTH_FAILURE listing the still-available methods
 * ("publickey,password"), and after a few the server sends SSH_MSG_DISCONNECT.
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
#include "sha256.h"        /* sha256_ctx: streaming exchange-hash transcript */

/* Buffer sizes. ib is PER-SLOT (it accumulates one client's inbound packets
 * across ticks); a single binary packet must fit it, and the client KEXINIT is
 * the largest (~1.1-1.5 KB). ob is a SHARED transient (see ssh.c): the tick is
 * single-threaded, so one outbound drain buffer is framed for the slot being
 * serviced and fully drained before the next. The exchange hash is computed
 * with a streaming SHA-256 over the transcript (a per-slot sha256_ctx), so the
 * old per-slot I_C copy is gone - the KEXINIT is hashed straight out of ib. */
#define SSH_IB_SZ   2048   /* inbound packet-accumulation buffer (per slot)  */
#define SSH_OB_SZ   2048   /* outbound drain buffer (shared transient)       */
#define SSH_IS_SZ    512   /* stored server KEXINIT payload  (I_S, per slot) */

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

/*
 * ssh_conn is now the PER-SLOT persistent state only (multi-client: one per
 * connection, ssh_slots[NCONN]). Everything that is pure transient scratch -
 * the outbound drain buffer, the exchange-hash preimage, the ECDH working
 * values, the decrypted-keystroke ring, the screen staging buffer - lives in a
 * single SHARED copy in ssh.c, reused non-reentrantly for whichever slot the
 * cooperative tick is servicing (see docs/DESIGN-ssh.md sec 4). Likewise the
 * host key, the password and the authorized-key set are the SAME for every
 * client, so they are process-global in ssh.c rather than replicated per slot.
 * What remains here is only what must survive across ticks for THIS client:
 * the transport state, its two session keys + sequence numbers, the session id,
 * the streaming exchange-hash transcript, the channel state, and the auth state.
 */
typedef struct ssh_conn {
	int          state;
	int          err;            /* nonzero once a fatal error is latched      */
	const char  *err_msg;        /* human-readable reason (native only)        */
	int          done;           /* 1 once SERVICE_REQUEST has been decrypted  */

	/* peer identification string, CR/LF stripped (V_C) - kept for the exchange
	 * hash (hashed at KEXINIT) and for logging. */
	char         cli_ver[256];
	unsigned     cli_ver_len;

	/* inbound accumulation (per slot: a partial packet spans ticks) */
	uint8_t      ib[SSH_IB_SZ]; unsigned ib_len;

	/* our KEXINIT payload (I_S), needed until it is folded into the exchange
	 * hash at the client's KEXINIT. */
	uint8_t      i_s[SSH_IS_SZ]; unsigned i_s_len;

	/* streaming exchange hash: V_C,V_S,I_C,I_S are folded in at KEXINIT and
	 * K_S,Q_C,Q_S,K at KEX_ECDH_INIT, then finalised to H. This replaces the
	 * per-slot I_C copy + one-shot preimage. */
	sha256_ctx   hctx;

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
 * Returns the number copied (0 when the queue is empty). Call in a loop. The
 * outbound queue is a single SHARED buffer (see ssh.c), framed for whichever
 * slot the tick is servicing and drained before the next - so drain it fully
 * for one slot before touching another. */
unsigned DOSSH_FAR ssh_output(ssh_conn *c, uint8_t *buf, unsigned max);

/* Discard whatever is left in the shared outbound queue. Used on teardown, when
 * a slot's transport is being aborted and its unsent bytes are moot - so they
 * cannot leak into the next slot's stream if its ring was full. */
void DOSSH_FAR ssh_discard_output(void);

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
 * empty/NULL string leaves the box open: the first auth attempt is accepted
 * (unless authorized keys are configured, which also gates the box). */
void DOSSH_FAR ssh_set_password(ssh_conn *c, const char *pw);

/* Configure the authorized ed25519 public keys for "publickey" auth (RFC 4252
 * sec 7). keys points at a persistent [count][32] byte array (raw 32-byte
 * ed25519 public keys) that must outlive the connection; ssh_conn keeps only
 * the pointer + count. Call AFTER ssh_reset. count == 0 (or never called)
 * leaves publickey unavailable. */
void DOSSH_FAR ssh_set_authorized_keys(ssh_conn *c, const uint8_t *keys,
                                       unsigned count);

/* Parse one OpenSSH authorized_keys line ("ssh-ed25519 <base64blob> [comment]")
 * into a raw 32-byte ed25519 public key. Returns 1 on success (pubkey filled),
 * 0 for a blank/comment/non-ed25519/malformed line. ssh-ed25519 only (the
 * crypto library has no RSA). */
int DOSSH_FAR ssh_parse_authkey_line(const char *line, uint8_t pubkey[32]);

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
 * is exhausted. Mirrors net_tx_flush. (Single-client path: serial + the native
 * harness. The multi-client net path uses ssh_channel_emit instead.) */
void DOSSH_FAR ssh_channel_flush(ssh_conn *c);

/* ---- multi-client screen tx: render once, encrypt per slot ---------
 * The shared screen render is produced once (plaintext), then each ready slot
 * frames+encrypts it with ITS OWN keys - no longer byte-identical across
 * clients (docs/DESIGN-ssh.md sec 4). These let the caller pace that per slot
 * without a per-slot staging buffer. */

/* Max plaintext bytes this channel can accept in ONE CHANNEL_DATA packet right
 * now: min(SSH_CHAN_CHUNK, peer_window, peer_maxpkt), or 0 if the channel is
 * not a live byte pipe. */
unsigned DOSSH_FAR ssh_channel_avail(ssh_conn *c);

/* Frame n plaintext bytes (1..ssh_channel_avail) as ONE encrypted CHANNEL_DATA
 * packet with this slot's keys into out[0..outmax); returns the wire length, or
 * 0 on error/overflow/closed. Advances send_seq and consumes peer_window. The
 * caller pushes the returned bytes onto this slot's transport. out needs room
 * for n + ~32 bytes. */
unsigned DOSSH_FAR ssh_channel_emit(ssh_conn *c, const uint8_t *plain,
                                    unsigned n, uint8_t *out, unsigned outmax);

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
