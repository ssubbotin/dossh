/*
 * ssh.c - DOSSH SSH-2.0 transport layer (RFC 4253). See ssh.h.
 *
 * A byte-fed, non-blocking state machine that carries a stock ssh client from
 * the version exchange through curve25519 key exchange to an encrypted
 * transport, then decrypts the client's first post-NEWKEYS packet and stops.
 * Everything the handshake needs is pulled from the __far crypto primitives
 * (crypto.h) and the CSPRNG (rng.h); no sockets, no libc I/O.
 *
 * Wire references: RFC 4253 (transport + key derivation sec 7.2), RFC 8731
 * (curve25519-sha256), RFC 5656 sec 4 (ECDH message shapes), RFC 8032
 * (ssh-ed25519), and OpenSSH's PROTOCOL.chacha20poly1305 (the record cipher).
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <string.h>          /* memcpy/memset/memmove/memcmp/strlen only */

#include "ssh.h"
#include "crypto.h"
#include "rng.h"

/* Our identification string. V_S is this without the trailing CR LF. */
#define SERVER_ID       "SSH-2.0-DOSSH_0.9"
#define SERVER_ID_CRLF  "SSH-2.0-DOSSH_0.9\r\n"

/* SSH message numbers (RFC 4253 sec 12, RFC 5656, RFC 4252, RFC 4254). */
#define MSG_DISCONNECT       1
#define MSG_IGNORE           2
#define MSG_UNIMPLEMENTED    3
#define MSG_DEBUG            4
#define MSG_SERVICE_REQUEST  5
#define MSG_SERVICE_ACCEPT   6
#define MSG_KEXINIT         20
#define MSG_NEWKEYS         21
#define MSG_KEX_ECDH_INIT   30
#define MSG_KEX_ECDH_REPLY  31
/* userauth (RFC 4252) */
#define MSG_USERAUTH_REQUEST 50
#define MSG_USERAUTH_FAILURE 51
#define MSG_USERAUTH_SUCCESS 52
#define MSG_USERAUTH_BANNER  53
#define MSG_USERAUTH_PK_OK   60   /* publickey probe accepted (RFC 4252 sec 7) */
/* connection protocol (RFC 4254) */
#define MSG_GLOBAL_REQUEST           80
#define MSG_REQUEST_SUCCESS          81
#define MSG_REQUEST_FAILURE          82
#define MSG_CHANNEL_OPEN             90
#define MSG_CHANNEL_OPEN_CONFIRMATION 91
#define MSG_CHANNEL_OPEN_FAILURE     92
#define MSG_CHANNEL_WINDOW_ADJUST    93
#define MSG_CHANNEL_DATA             94
#define MSG_CHANNEL_EXTENDED_DATA    95
#define MSG_CHANNEL_EOF              96
#define MSG_CHANNEL_CLOSE            97
#define MSG_CHANNEL_REQUEST          98
#define MSG_CHANNEL_SUCCESS          99
#define MSG_CHANNEL_FAILURE         100

/* SSH_MSG_DISCONNECT reason code used when auth is exhausted (RFC 4253 sec 11). */
#define DISCONNECT_NO_MORE_AUTH      14
/* SSH_MSG_CHANNEL_OPEN_FAILURE reason codes (RFC 4254 sec 5.1). */
#define OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define OPEN_UNKNOWN_CHANNEL_TYPE        3

/*
 * Transient scratch for the exchange-hash preimage and the KDF. It is written
 * and consumed entirely within a single kex step and never carries state
 * between calls, so a file-static (shared, non-reentrant) buffer is correct
 * for the cooperative tick and saves per-slot DGROUP - the same pattern rng.c
 * uses. Sized for the largest preimage: string-wrapped V_C, V_S, I_C, I_S,
 * K_S, Q_C, Q_S plus the mpint K.
 */
static uint8_t g_scratch[SSH_IC_SZ + SSH_IS_SZ + 512];

/* ---- small byte helpers -------------------------------------------- */

static void put_u32(uint8_t *d, uint32_t v)
{
	d[0] = (uint8_t)(v >> 24); d[1] = (uint8_t)(v >> 16);
	d[2] = (uint8_t)(v >> 8);  d[3] = (uint8_t)v;
}

static uint32_t rd_u32(const uint8_t *d)
{
	return ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) |
	       ((uint32_t)d[2] << 8)  |  (uint32_t)d[3];
}

/* chacha20-poly1305@openssh.com nonce: the 64-bit packet sequence number,
 * big-endian, as the 8-byte DJB nonce (matches OpenSSH's POKE_U64(seqnr)). */
static void seqbuf8(uint32_t seq, uint8_t out[8])
{
	out[0] = out[1] = out[2] = out[3] = 0;
	out[4] = (uint8_t)(seq >> 24); out[5] = (uint8_t)(seq >> 16);
	out[6] = (uint8_t)(seq >> 8);  out[7] = (uint8_t)seq;
}

/* write an SSH string (uint32 length + bytes); return bytes written */
static unsigned put_str(uint8_t *d, const uint8_t *s, unsigned n)
{
	put_u32(d, n);
	if (n) memcpy(d + 4, s, n);
	return 4 + n;
}

/* write a name-list (an SSH string of comma-joined names) from a C literal */
static unsigned put_nl(uint8_t *d, const char *s)
{
	unsigned n = (unsigned)strlen(s);
	return put_str(d, (const uint8_t *)s, n);
}

static void fail(ssh_conn *c, const char *why)
{
	if (c->state != SSH_ST_ERROR) {
		c->state = SSH_ST_ERROR;
		c->err = 1;
		c->err_msg = why;
	}
}

/* ---- output queue --------------------------------------------------- */

static void ob_append(ssh_conn *c, const uint8_t *d, unsigned n)
{
	if (c->ob_len + n > SSH_OB_SZ) { fail(c, "output overflow"); return; }
	memcpy(c->ob + c->ob_len, d, n);
	c->ob_len += n;
}

/* drop k consumed bytes from the front of the inbound buffer */
static void ib_consume(ssh_conn *c, unsigned k)
{
	if (k >= c->ib_len) c->ib_len = 0;
	else { memmove(c->ib, c->ib + k, c->ib_len - k); c->ib_len -= k; }
}

/* ---- binary packet framing: send ----------------------------------- */

/* unencrypted (pre-NEWKEYS) packet: length field counted in the block size */
static void send_unenc(ssh_conn *c, const uint8_t *payload, unsigned plen)
{
	uint8_t hdr[5], pad[32];
	unsigned padlen, pkt_len;

	padlen = 8 - ((4 + 1 + plen) % 8);
	if (padlen < 4) padlen += 8;
	pkt_len = 1 + plen + padlen;

	put_u32(hdr, pkt_len);
	hdr[4] = (uint8_t)padlen;
	ob_append(c, hdr, 5);
	ob_append(c, payload, plen);
	rng_bytes(pad, padlen);
	ob_append(c, pad, padlen);
	c->send_seq++;
}

/*
 * chacha20-poly1305@openssh.com packet (RFC-style body, OpenSSH framing):
 *   enc_len(4)  = packet_length XOR header-key keystream (ctr 0)
 *   enc_body(N) = [padlen | payload | padding] XOR main-key keystream (ctr 1)
 *   tag(16)     = Poly1305(enc_len || enc_body), key = main-key block 0 [0..31]
 * The 4-byte length field is NOT counted in the block-size padding here.
 */
static void send_enc(ssh_conn *c, const uint8_t *payload, unsigned plen)
{
	uint8_t *k_main   = c->ek_s2c;        /* [0..31]  */
	uint8_t *k_header = c->ek_s2c + 32;   /* [32..63] */
	uint8_t nonce[8], enc_len[4], polykey[32], tag[16], body[256];
	unsigned padlen, pkt_len, start;

	if (1 + plen + 8 > sizeof(body)) { fail(c, "enc payload too large"); return; }

	padlen = 8 - ((1 + plen) % 8);
	if (padlen < 4) padlen += 8;
	pkt_len = 1 + plen + padlen;

	body[0] = (uint8_t)padlen;
	if (plen) memcpy(body + 1, payload, plen);
	rng_bytes(body + 1 + plen, padlen);

	seqbuf8(c->send_seq, nonce);

	put_u32(enc_len, pkt_len);
	dossh_chacha20_djb(enc_len, enc_len, 4, k_header, nonce, 0);
	dossh_chacha20_djb(polykey, (const uint8_t *)0, 32, k_main, nonce, 0);
	dossh_chacha20_djb(body, body, pkt_len, k_main, nonce, 1);

	start = c->ob_len;
	ob_append(c, enc_len, 4);
	ob_append(c, body, pkt_len);
	if (c->state == SSH_ST_ERROR) return;
	dossh_poly1305(tag, c->ob + start, 4 + pkt_len, polykey);
	ob_append(c, tag, 16);
	c->send_seq++;
}

static void send_packet(ssh_conn *c, const uint8_t *payload, unsigned plen)
{
	if (c->send_encrypted) send_enc(c, payload, plen);
	else                   send_unenc(c, payload, plen);
}

/* ---- name-list parsing --------------------------------------------- */

static int nl_has(const uint8_t *list, unsigned len, const char *name)
{
	unsigned i = 0, start = 0, nlen = (unsigned)strlen(name);
	for (;;) {
		if (i == len || list[i] == ',') {
			unsigned tlen = i - start;
			if (tlen == nlen && memcmp(list + start, name, nlen) == 0)
				return 1;
			if (i == len) return 0;
			start = i + 1;
		}
		i++;
	}
}

/* first token of a name-list (up to the first comma or the end) */
static void nl_first(const uint8_t *list, unsigned len,
                     const uint8_t **tok, unsigned *tlen)
{
	unsigned i = 0;
	while (i < len && list[i] != ',') i++;
	*tok = list; *tlen = i;
}

static int tok_eq(const uint8_t *tok, unsigned tlen, const char *s)
{
	unsigned n = (unsigned)strlen(s);
	return tlen == n && memcmp(tok, s, n) == 0;
}

/* ---- KEXINIT -------------------------------------------------------- */

static void build_our_kexinit(ssh_conn *c)
{
	uint8_t *b = c->i_s;
	unsigned o = 0;

	b[o++] = MSG_KEXINIT;
	rng_bytes(b + o, 16); o += 16;                       /* cookie */
	o += put_nl(b + o, "curve25519-sha256,curve25519-sha256@libssh.org");
	o += put_nl(b + o, "ssh-ed25519");
	o += put_nl(b + o, "chacha20-poly1305@openssh.com"); /* enc c->s */
	o += put_nl(b + o, "chacha20-poly1305@openssh.com"); /* enc s->c */
	o += put_nl(b + o, "none");                          /* mac c->s (AEAD) */
	o += put_nl(b + o, "none");                          /* mac s->c (AEAD) */
	o += put_nl(b + o, "none");                          /* comp c->s */
	o += put_nl(b + o, "none");                          /* comp s->c */
	o += put_nl(b + o, "");                              /* lang c->s */
	o += put_nl(b + o, "");                              /* lang s->c */
	b[o++] = 0;                                          /* first_kex_follows */
	b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0;      /* reserved */
	c->i_s_len = o;
}

/* verify the client offers what we require and set up the guess handling */
static int negotiate(ssh_conn *c)
{
	const uint8_t *p = c->i_c, *lists[10];
	unsigned len = c->i_c_len, off = 17, llen[10];   /* skip msg(1)+cookie(16) */
	const uint8_t *tok; unsigned tlen;
	int idx, kex_ok, hk_ok;

	for (idx = 0; idx < 10; idx++) {
		unsigned l;
		if (off + 4 > len) return -1;
		l = rd_u32(p + off); off += 4;
		if (off + l > len) return -1;
		lists[idx] = p + off; llen[idx] = l; off += l;
	}
	if (off + 1 > len) return -1;
	c->cli_first_follows = p[off];

	if (!(nl_has(lists[0], llen[0], "curve25519-sha256") ||
	      nl_has(lists[0], llen[0], "curve25519-sha256@libssh.org")))
		return -2;
	if (!nl_has(lists[1], llen[1], "ssh-ed25519"))                     return -2;
	if (!nl_has(lists[2], llen[2], "chacha20-poly1305@openssh.com"))   return -2;
	if (!nl_has(lists[3], llen[3], "chacha20-poly1305@openssh.com"))   return -2;

	nl_first(lists[0], llen[0], &tok, &tlen);
	kex_ok = tok_eq(tok, tlen, "curve25519-sha256") ||
	         tok_eq(tok, tlen, "curve25519-sha256@libssh.org");
	nl_first(lists[1], llen[1], &tok, &tlen);
	hk_ok = tok_eq(tok, tlen, "ssh-ed25519");
	c->discard_next = (c->cli_first_follows && !(kex_ok && hk_ok)) ? 1 : 0;
	return 0;
}

/* ---- exchange hash + key derivation -------------------------------- */

/* encode the raw 32-byte shared secret as an SSH mpint (into c->kmpint) */
static void build_kmpint(ssh_conn *c)
{
	const uint8_t *v = c->k_raw;
	unsigned i = 0, o, n, pad;

	while (i < 32 && v[i] == 0) i++;
	n = 32 - i;
	if (n == 0) { put_u32(c->kmpint, 0); c->kmpint_len = 4; return; }
	pad = (v[i] & 0x80) ? 1 : 0;
	put_u32(c->kmpint, n + pad); o = 4;
	if (pad) c->kmpint[o++] = 0;
	memcpy(c->kmpint + o, v + i, n); o += n;
	c->kmpint_len = o;
}

static void build_ks_blob(ssh_conn *c)
{
	unsigned o = 0;
	o += put_str(c->ks_blob + o, (const uint8_t *)"ssh-ed25519", 11);
	o += put_str(c->ks_blob + o, c->hostkey_pk, 32);
	c->ks_len = o;
}

/* H = SHA256( string(V_C) string(V_S) string(I_C) string(I_S)
 *             string(K_S) string(Q_C) string(Q_S) mpint(K) ) */
static void compute_H(ssh_conn *c)
{
	unsigned o = 0;
	o += put_str(g_scratch + o, (const uint8_t *)c->cli_ver, c->cli_ver_len);
	o += put_str(g_scratch + o, (const uint8_t *)SERVER_ID,
	             (unsigned)strlen(SERVER_ID));
	o += put_str(g_scratch + o, c->i_c, c->i_c_len);
	o += put_str(g_scratch + o, c->i_s, c->i_s_len);
	o += put_str(g_scratch + o, c->ks_blob, c->ks_len);
	o += put_str(g_scratch + o, c->q_c, 32);
	o += put_str(g_scratch + o, c->q_s, 32);
	memcpy(g_scratch + o, c->kmpint, c->kmpint_len); o += c->kmpint_len;
	dossh_sha256(c->H, g_scratch, o);
}

/*
 * RFC 4253 sec 7.2 key derivation:
 *   K1 = HASH(K || H || <letter> || session_id)
 *   Kn = HASH(K || H || K1 || ... || K(n-1))
 *   key = K1 || K2 || ...   (truncated to outlen)
 * K is the mpint encoding (c->kmpint), H is 32 bytes, session_id is 32 bytes.
 */
static void derive_key(ssh_conn *c, uint8_t letter, uint8_t *out, unsigned outlen)
{
	uint8_t buf[40 + 32 + 1 + 32 + 64], block[32];
	unsigned blen, produced, take;

	blen = 0;
	memcpy(buf, c->kmpint, c->kmpint_len);        blen = c->kmpint_len;
	memcpy(buf + blen, c->H, 32);                 blen += 32;
	buf[blen++] = letter;
	memcpy(buf + blen, c->session_id, 32);        blen += 32;
	dossh_sha256(block, buf, blen);
	take = outlen < 32 ? outlen : 32;
	memcpy(out, block, take); produced = take;

	while (produced < outlen) {
		blen = 0;
		memcpy(buf, c->kmpint, c->kmpint_len);    blen = c->kmpint_len;
		memcpy(buf + blen, c->H, 32);             blen += 32;
		memcpy(buf + blen, out, produced);        blen += produced;
		dossh_sha256(block, buf, blen);
		take = (outlen - produced) < 32 ? (outlen - produced) : 32;
		memcpy(out + produced, block, take); produced += take;
	}
	memset(buf, 0, sizeof(buf));
	memset(block, 0, sizeof(block));
}

/* ---- per-message handlers ------------------------------------------ */

static void handle_kexinit(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	int r;
	if (plen > SSH_IC_SZ) { fail(c, "KEXINIT too large"); return; }
	memcpy(c->i_c, pl, plen); c->i_c_len = plen;
	r = negotiate(c);
	if (r == -1) { fail(c, "malformed KEXINIT"); return; }
	if (r == -2) { fail(c, "no common algorithm"); return; }
	c->state = SSH_ST_EXPECT_ECDH_INIT;
}

static void handle_ecdh_init(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	uint8_t rep[256], sigblob[100], sig[64];
	unsigned o, so, qlen;

	if (c->discard_next) { c->discard_next = 0; return; }  /* wrong kex guess */
	if (plen < 5) { fail(c, "short KEX_ECDH_INIT"); return; }
	qlen = rd_u32(pl + 1);
	if (qlen != 32 || 1 + 4 + qlen > plen) { fail(c, "bad Q_C"); return; }
	memcpy(c->q_c, pl + 5, 32);

	/* server ephemeral + shared secret */
	rng_bytes(c->eph_sk, 32);
	dossh_x25519_public_key(c->q_s, c->eph_sk);
	dossh_x25519(c->k_raw, c->eph_sk, c->q_c);

	/* reject a low-order Q_C that forces an all-zero shared secret */
	{
		uint8_t z = 0;
		for (o = 0; o < 32; o++) z |= c->k_raw[o];
		if (z == 0) { fail(c, "degenerate shared secret"); return; }
	}

	build_kmpint(c);
	build_ks_blob(c);
	compute_H(c);
	if (!c->have_session_id) {
		memcpy(c->session_id, c->H, 32);
		c->have_session_id = 1;
	}

	/* SSH_MSG_KEX_ECDH_REPLY: K_S, Q_S, signature-of-H blob */
	dossh_ed25519_sign(sig, c->hostkey_sk, c->H, 32);
	so  = put_str(sigblob, (const uint8_t *)"ssh-ed25519", 11);
	so += put_str(sigblob + so, sig, 64);

	o = 0;
	rep[o++] = MSG_KEX_ECDH_REPLY;
	o += put_str(rep + o, c->ks_blob, c->ks_len);
	o += put_str(rep + o, c->q_s, 32);
	o += put_str(rep + o, sigblob, so);
	send_packet(c, rep, o);

	/* derive session keys, then NEWKEYS, then switch our side to encrypt */
	derive_key(c, 'C', c->ek_c2s, 64);   /* client->server (we decrypt) */
	derive_key(c, 'D', c->ek_s2c, 64);   /* server->client (we encrypt) */
	c->keys_ready = 1;

	{
		uint8_t nk = MSG_NEWKEYS;
		send_packet(c, &nk, 1);
	}
	c->send_encrypted = 1;
	c->state = SSH_ST_EXPECT_CLIENT_NEWKEYS;
}

static void handle_client_newkeys(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	(void)pl; (void)plen;
	c->recv_encrypted = 1;      /* everything the client sends now is encrypted */
	c->state = SSH_ST_EXPECT_SERVICE_REQUEST;
}

static void handle_service_request(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	uint8_t accept[80];
	unsigned slen, o;

	if (plen < 5) { fail(c, "short SERVICE_REQUEST"); return; }
	slen = rd_u32(pl + 1);
	if (1 + 4 + slen > plen || slen >= sizeof(c->svc_name)) {
		fail(c, "bad service name"); return;
	}
	memcpy(c->svc_name, pl + 5, slen);
	c->svc_name[slen] = 0;
	c->done = 1;                 /* latched: SERVICE_REQUEST decrypted           */

	/* SERVICE_ACCEPT echoes the requested service (RFC 4253 sec 10). */
	o = 0;
	accept[o++] = MSG_SERVICE_ACCEPT;
	o += put_str(accept + o, (const uint8_t *)c->svc_name, slen);
	send_packet(c, accept, o);

	c->state = SSH_ST_AUTH;      /* now run userauth on top of the transport     */
}

/* ---- userauth (RFC 4252) ------------------------------------------- */

static void send_userauth_failure(ssh_conn *c)
{
	uint8_t rep[64];
	char methods[32];
	unsigned o = 0, m = 0;

	/* Advertise exactly the methods that can still authenticate, so a client
	 * with an authorized key tries publickey (and never puts a secret on the
	 * wire) while password still works otherwise. */
	if (c->authkey_count) { memcpy(methods + m, "publickey", 9); m += 9; }
	if (c->have_password) {
		if (m) methods[m++] = ',';
		memcpy(methods + m, "password", 8); m += 8;
	}
	if (m == 0) { memcpy(methods, "password", 8); m = 8; }  /* never empty */
	methods[m] = 0;

	rep[o++] = MSG_USERAUTH_FAILURE;
	o += put_nl(rep + o, methods);      /* methods that can still continue */
	rep[o++] = 0;                       /* partial success = FALSE          */
	send_packet(c, rep, o);
}

static void send_userauth_success(ssh_conn *c)
{
	uint8_t m = MSG_USERAUTH_SUCCESS;
	send_packet(c, &m, 1);
	c->authenticated = 1;
	c->state = SSH_ST_SESSION;
}

static void send_disconnect(ssh_conn *c, uint32_t reason, const char *desc)
{
	uint8_t rep[96];
	unsigned o = 0;
	rep[o++] = MSG_DISCONNECT;
	put_u32(rep + o, reason); o += 4;
	o += put_nl(rep + o, desc);
	o += put_nl(rep + o, "");           /* language tag */
	send_packet(c, rep, o);
	c->state = SSH_ST_CLOSED;
}

static void auth_reject(ssh_conn *c, int count_it)
{
	if (count_it) c->auth_fails++;
	if (c->auth_fails >= SSH_MAX_AUTH_TRIES)
		send_disconnect(c, DISCONNECT_NO_MORE_AUTH,
		                "too many authentication failures");
	else
		send_userauth_failure(c);
}

/*
 * Bounds-checked SSH string reader: at *po, read a uint32 length then that many
 * bytes, all within [0,plen). On success returns 1 with the pointer/length set
 * and *po advanced; on any overrun returns 0, leaving the caller to reject. Every
 * length field from the wire flows through here so nothing is ever read out of
 * bounds - the arithmetic can't wrap (o <= plen is an invariant, and the body
 * length is compared in 32-bit before it is narrowed). */
static int rd_string(const uint8_t *pl, unsigned plen, unsigned *po,
                     const uint8_t **s, unsigned *slen)
{
	unsigned o = *po;
	uint32_t L;
	if (o > plen || plen - o < 4) return 0;
	L = rd_u32(pl + o);
	if (L > (uint32_t)(plen - o - 4)) return 0;   /* body must fit the packet */
	o += 4;
	*s = pl + o;
	*slen = (unsigned)L;                          /* L <= plen: fits 16-bit    */
	o += (unsigned)L;
	*po = o;
	return 1;
}

/* Pull the raw 32-byte ed25519 public key out of an "ssh-ed25519" key blob
 * (string("ssh-ed25519") string(key32)). Returns a pointer to the 32 key bytes
 * inside blob, or 0 if the blob is malformed / not exactly this shape. */
static const uint8_t *ed25519_key_from_blob(const uint8_t *blob, unsigned bloblen)
{
	unsigned o = 0, klen;
	const uint8_t *name, *key;
	unsigned nlen;
	if (!rd_string(blob, bloblen, &o, &name, &nlen)) return 0;
	if (nlen != 11 || memcmp(name, "ssh-ed25519", 11) != 0) return 0;
	if (!rd_string(blob, bloblen, &o, &key, &klen)) return 0;
	if (klen != 32) return 0;
	return key;
}

/* Pull the raw 64-byte ed25519 signature out of a signature blob
 * (string("ssh-ed25519") string(sig64)). Returns a pointer to the 64 sig bytes,
 * or 0 if malformed / wrong algorithm / wrong length. */
static const uint8_t *ed25519_sig_from_blob(const uint8_t *sb, unsigned sblen)
{
	unsigned o = 0, glen;
	const uint8_t *name, *sig;
	unsigned nlen;
	if (!rd_string(sb, sblen, &o, &name, &nlen)) return 0;
	if (nlen != 11 || memcmp(name, "ssh-ed25519", 11) != 0) return 0;
	if (!rd_string(sb, sblen, &o, &sig, &glen)) return 0;
	if (glen != 64) return 0;
	return sig;
}

/* Is this 32-byte ed25519 public key in the configured authorized set? Keys are
 * public, so a plain compare is fine (no secret-dependent timing here). */
static int authkey_is_authorized(ssh_conn *c, const uint8_t *key)
{
	unsigned i;
	for (i = 0; i < c->authkey_count; i++)
		if (memcmp(c->authkeys + (unsigned)i * 32, key, 32) == 0)
			return 1;
	return 0;
}

/* SSH_MSG_USERAUTH_PK_OK: echo the offered algorithm name + key blob so the
 * client knows this key is acceptable and proceeds to sign (RFC 4252 sec 7). */
static void send_pk_ok(ssh_conn *c, const uint8_t *algo, unsigned algolen,
                       const uint8_t *blob, unsigned bloblen)
{
	uint8_t rep[128];
	unsigned o = 0;
	if (1 + 4 + algolen + 4 + bloblen > sizeof(rep)) { auth_reject(c, 1); return; }
	rep[o++] = MSG_USERAUTH_PK_OK;
	o += put_str(rep + o, algo, algolen);
	o += put_str(rep + o, blob, bloblen);
	send_packet(c, rep, o);
}

/*
 * Reconstruct, into g_scratch, the exact byte string a publickey signature is
 * computed over (RFC 4252 sec 7):
 *   string(session_id) byte(SSH_MSG_USERAUTH_REQUEST) string(user)
 *   string(service) string("publickey") boolean(TRUE)
 *   string(pubkey-algorithm) string(pubkey-blob)
 * The user/service/algo/blob bytes are used verbatim as the client sent them.
 * g_scratch (>= 3 KB) is free after key exchange, so no extra DGROUP is spent.
 * Returns the length written. */
static unsigned build_pk_signed_data(ssh_conn *c,
        const uint8_t *user, unsigned ulen,
        const uint8_t *service, unsigned slen,
        const uint8_t *algo, unsigned algolen,
        const uint8_t *blob, unsigned bloblen)
{
	unsigned o = 0;
	o += put_str(g_scratch + o, c->session_id, 32);
	g_scratch[o++] = MSG_USERAUTH_REQUEST;
	o += put_str(g_scratch + o, user, ulen);
	o += put_str(g_scratch + o, service, slen);
	o += put_str(g_scratch + o, (const uint8_t *)"publickey", 9);
	g_scratch[o++] = 1;                              /* boolean TRUE */
	o += put_str(g_scratch + o, algo, algolen);
	o += put_str(g_scratch + o, blob, bloblen);
	return o;
}

/*
 * publickey userauth (RFC 4252 sec 7), ssh-ed25519 only. o is the packet offset
 * just past the "publickey" method name (i.e. at the boolean). Two forms:
 *   probe  (boolean FALSE, no signature): reply PK_OK iff the offered key is
 *          authorized, else FAILURE. A probe NEVER grants authentication.
 *   signed (boolean TRUE, with a signature): grant SUCCESS iff the key is
 *          authorized AND the ed25519 signature verifies over the session-bound
 *          data above; otherwise FAILURE. Both conditions must hold.
 */
static void handle_pubkey_auth(ssh_conn *c, const uint8_t *pl, unsigned plen,
                               unsigned o,
                               const uint8_t *user, unsigned ulen,
                               const uint8_t *service, unsigned slen)
{
	const uint8_t *algo, *blob, *key, *sigblob, *rawsig;
	unsigned algolen, bloblen, siglen, dlen;
	uint8_t have_sig;
	int authorized;

	if (o + 1 > plen) { auth_reject(c, 1); return; }
	have_sig = pl[o++];
	if (!rd_string(pl, plen, &o, &algo, &algolen)) { auth_reject(c, 1); return; }
	if (!rd_string(pl, plen, &o, &blob, &bloblen)) { auth_reject(c, 1); return; }

	/* ssh-ed25519 is the only publickey algorithm we implement (the crypto lib
	 * has no RSA); anything else fails cleanly so the client can fall back. */
	if (algolen != 11 || memcmp(algo, "ssh-ed25519", 11) != 0) {
		auth_reject(c, 1); return;
	}
	key = ed25519_key_from_blob(blob, bloblen);
	if (!key) { auth_reject(c, 1); return; }

	authorized = authkey_is_authorized(c, key);

	if (!have_sig) {                    /* PROBE: PK_OK only, never SUCCESS */
		if (!authorized) { auth_reject(c, 1); return; }
		send_pk_ok(c, algo, algolen, blob, bloblen);
		return;
	}

	/* Signed request: the signature blob follows the key blob. */
	if (!rd_string(pl, plen, &o, &sigblob, &siglen)) { auth_reject(c, 1); return; }
	rawsig = ed25519_sig_from_blob(sigblob, siglen);
	if (!rawsig) { auth_reject(c, 1); return; }

	/* Authorization AND a valid signature over the session-bound data must both
	 * hold. Verifying the offered key's own signature is not enough - the key
	 * must also be in the authorized set. */
	if (!authorized) { auth_reject(c, 1); return; }
	dlen = build_pk_signed_data(c, user, ulen, service, slen,
	                            algo, algolen, blob, bloblen);
	if (dossh_ed25519_verify(rawsig, key, g_scratch, dlen) == 0)
		send_userauth_success(c);
	else
		auth_reject(c, 1);
}

static void handle_userauth_request(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	unsigned o = 1, ulen, slen, mlen, k;
	const uint8_t *user, *service, *method;

	if (!rd_string(pl, plen, &o, &user, &ulen))    { fail(c, "short USERAUTH_REQUEST"); return; }
	if (!rd_string(pl, plen, &o, &service, &slen)) { fail(c, "bad USERAUTH_REQUEST"); return; }
	if (!rd_string(pl, plen, &o, &method, &mlen))  { fail(c, "bad USERAUTH_REQUEST"); return; }

	k = ulen < sizeof(c->auth_user) - 1 ? ulen : sizeof(c->auth_user) - 1;
	memcpy(c->auth_user, user, k); c->auth_user[k] = 0;

	/* Open box (no /P equivalent, no authorized keys): admit the first attempt,
	 * any method. Once a password OR authorized keys are configured, the box is
	 * gated and only a matching credential authenticates. */
	if (!c->have_password && !c->authkey_count) { send_userauth_success(c); return; }

	if (mlen == 9 && memcmp(method, "publickey", 9) == 0) {
		if (!c->authkey_count) { auth_reject(c, 1); return; }  /* not offered */
		handle_pubkey_auth(c, pl, plen, o, user, ulen, service, slen);
		return;
	}

	if (c->have_password && mlen == 8 && memcmp(method, "password", 8) == 0) {
		unsigned pwlen, want;
		const uint8_t *pw;
		if (o + 1 > plen) { auth_reject(c, 1); return; }
		if (pl[o++]) { auth_reject(c, 1); return; }  /* change-password: no */
		if (!rd_string(pl, plen, &o, &pw, &pwlen)) { auth_reject(c, 1); return; }
		want = (unsigned)strlen(c->password);
		if (pwlen == want && memcmp(pw, c->password, want) == 0)
			send_userauth_success(c);
		else
			auth_reject(c, 1);
		return;
	}

	/* "none" is the client's probe for the method list - don't spend the retry
	 * budget on it; any other unsupported method counts. */
	auth_reject(c, !(mlen == 4 && memcmp(method, "none", 4) == 0));
}

/* ---- connection layer (RFC 4254) ----------------------------------- */

static void chan_reply(ssh_conn *c, uint8_t type)   /* SUCCESS/FAILURE */
{
	uint8_t rep[8];
	rep[0] = type;
	put_u32(rep + 1, c->peer_chan);
	send_packet(c, rep, 5);
}

static void handle_channel_open(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	unsigned o = 1, tlen;
	const uint8_t *tname;
	uint32_t sender, iwin, maxp;
	uint8_t rep[64];
	unsigned ro;

	if (o + 4 > plen) { fail(c, "short CHANNEL_OPEN"); return; }
	tlen = rd_u32(pl + o); o += 4; tname = pl + o; o += tlen;
	if (o + 12 > plen) { fail(c, "bad CHANNEL_OPEN"); return; }
	sender = rd_u32(pl + o); o += 4;
	iwin   = rd_u32(pl + o); o += 4;
	maxp   = rd_u32(pl + o); o += 4;

	if (c->chan_open || tlen != 7 || memcmp(tname, "session", 7) != 0) {
		ro = 0;
		rep[ro++] = MSG_CHANNEL_OPEN_FAILURE;
		put_u32(rep + ro, sender); ro += 4;
		put_u32(rep + ro, c->chan_open ? OPEN_ADMINISTRATIVELY_PROHIBITED
		                               : OPEN_UNKNOWN_CHANNEL_TYPE); ro += 4;
		ro += put_nl(rep + ro, "only one session channel");
		ro += put_nl(rep + ro, "");
		send_packet(c, rep, ro);
		return;
	}

	c->peer_chan     = sender;
	c->peer_window   = iwin;
	c->peer_maxpkt   = maxp;
	c->local_chan    = 0;
	c->local_window  = SSH_LOCAL_WINDOW;
	c->chan_open     = 1;

	ro = 0;
	rep[ro++] = MSG_CHANNEL_OPEN_CONFIRMATION;
	put_u32(rep + ro, sender);           ro += 4;   /* recipient (their id)  */
	put_u32(rep + ro, c->local_chan);    ro += 4;   /* our sender id          */
	put_u32(rep + ro, c->local_window);  ro += 4;   /* our initial window     */
	put_u32(rep + ro, SSH_CHAN_MAXPKT);  ro += 4;   /* our max packet size    */
	send_packet(c, rep, ro);
}

static void handle_channel_request(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	unsigned o = 1, rtlen;
	const uint8_t *rtype;
	int want_reply, granted = 0;

	if (o + 4 > plen) return;
	o += 4;                                        /* recipient channel (ours) */
	if (o + 4 > plen) return;
	rtlen = rd_u32(pl + o); o += 4; rtype = pl + o; o += rtlen;
	if (o + 1 > plen) return;
	want_reply = pl[o++];

	if (rtlen == 7 && memcmp(rtype, "pty-req", 7) == 0) {
		unsigned tl;                               /* TERM string, then WxH */
		if (o + 4 <= plen) {
			tl = rd_u32(pl + o); o += 4 + tl;
			if (o + 8 <= plen) {
				c->term_cols = rd_u32(pl + o);
				c->term_rows = rd_u32(pl + o + 4);
			}
		}
		c->pty = 1;
		granted = 1;
	} else if ((rtlen == 5 && memcmp(rtype, "shell", 5) == 0) ||
	           (rtlen == 4 && memcmp(rtype, "exec", 4) == 0)) {
		c->shell_ready = 1;                        /* channel is now a byte pipe */
		granted = 1;
	} else if (rtlen == 13 && memcmp(rtype, "window-change", 13) == 0) {
		if (o + 8 <= plen) {
			c->term_cols = rd_u32(pl + o);
			c->term_rows = rd_u32(pl + o + 4);
		}
		granted = 1;                               /* want_reply is always 0 */
	} else {
		granted = 0;                               /* env / signal / unknown */
	}

	if (want_reply)
		chan_reply(c, granted ? MSG_CHANNEL_SUCCESS : MSG_CHANNEL_FAILURE);
}

static void adjust_local_window(ssh_conn *c, unsigned consumed)
{
	uint8_t adj[9];
	unsigned o, add;

	if (c->local_window >= consumed) c->local_window -= consumed;
	else                             c->local_window = 0;
	if (c->local_window >= SSH_LOCAL_WINDOW / 2) return;

	add = SSH_LOCAL_WINDOW - c->local_window;
	o = 0;
	adj[o++] = MSG_CHANNEL_WINDOW_ADJUST;
	put_u32(adj + o, c->peer_chan); o += 4;
	put_u32(adj + o, add);          o += 4;
	send_packet(c, adj, o);
	c->local_window += add;
}

static void handle_channel_data(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	unsigned dlen, i;

	if (plen < 9) return;                          /* msg + chan(4) + len(4) */
	dlen = rd_u32(pl + 5);
	if (9 + dlen > plen) dlen = plen - 9;          /* clamp to what arrived  */
	for (i = 0; i < dlen; i++) {
		unsigned next = (c->cin_tail + 1) % SSH_CIN_SZ;
		if (next == c->cin_head) break;            /* ring full: drop the rest */
		c->cin[c->cin_tail] = pl[9 + i];
		c->cin_tail = next;
	}
	adjust_local_window(c, dlen);
}

static void handle_channel_window_adjust(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	if (plen < 9) return;
	c->peer_window += rd_u32(pl + 5);
}

static void handle_global_request(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	unsigned o = 1, nlen;
	if (o + 4 > plen) return;
	nlen = rd_u32(pl + o); o += 4 + nlen;
	if (o < plen && pl[o]) {                        /* want_reply */
		uint8_t m = MSG_REQUEST_FAILURE;
		send_packet(c, &m, 1);
	}
}

static void handle_packet(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	uint8_t msg = plen ? pl[0] : 0;

	/* messages allowed at any time */
	if (msg == MSG_DISCONNECT) { c->state = SSH_ST_CLOSED; return; }
	if (msg == MSG_IGNORE || msg == MSG_DEBUG || msg == MSG_UNIMPLEMENTED)
		return;
	if (msg == MSG_GLOBAL_REQUEST) { handle_global_request(c, pl, plen); return; }

	switch (c->state) {
	case SSH_ST_EXPECT_KEXINIT:
		if (msg != MSG_KEXINIT) { fail(c, "expected KEXINIT"); return; }
		handle_kexinit(c, pl, plen);
		return;
	case SSH_ST_EXPECT_ECDH_INIT:
		if (msg != MSG_KEX_ECDH_INIT && !c->discard_next) {
			fail(c, "expected KEX_ECDH_INIT"); return;
		}
		handle_ecdh_init(c, pl, plen);
		return;
	case SSH_ST_EXPECT_CLIENT_NEWKEYS:
		if (msg != MSG_NEWKEYS) { fail(c, "expected NEWKEYS"); return; }
		handle_client_newkeys(c, pl, plen);
		return;
	case SSH_ST_EXPECT_SERVICE_REQUEST:
		if (msg != MSG_SERVICE_REQUEST) {
			fail(c, "expected SERVICE_REQUEST"); return;
		}
		handle_service_request(c, pl, plen);
		return;
	case SSH_ST_AUTH:
		if (msg == MSG_USERAUTH_REQUEST) handle_userauth_request(c, pl, plen);
		/* else ignore stray traffic while authenticating */
		return;
	case SSH_ST_SESSION:
		switch (msg) {
		case MSG_CHANNEL_OPEN:          handle_channel_open(c, pl, plen);   break;
		case MSG_CHANNEL_REQUEST:       handle_channel_request(c, pl, plen);break;
		case MSG_CHANNEL_DATA:          handle_channel_data(c, pl, plen);   break;
		case MSG_CHANNEL_WINDOW_ADJUST: handle_channel_window_adjust(c, pl, plen); break;
		case MSG_CHANNEL_EOF:           c->chan_eof = 1;                    break;
		case MSG_CHANNEL_CLOSE:
			if (!c->chan_sent_close) ssh_channel_close(c);
			c->chan_closed = 1;
			c->state = SSH_ST_CLOSED;
			break;
		default: /* CHANNEL_EXTENDED_DATA and anything else: ignore */      break;
		}
		return;
	default:
		fail(c, "unexpected packet");
		return;
	}
}

/* ---- inbound decode ------------------------------------------------- */

/* consume one line of the version exchange; 1 = progressed, 0 = need more */
static int try_version(ssh_conn *c)
{
	unsigned i;
	for (i = 0; i < c->ib_len; i++) {
		if (c->ib[i] == '\n') {
			unsigned linelen = i;
			if (linelen && c->ib[linelen - 1] == '\r') linelen--;
			if (linelen >= 4 && memcmp(c->ib, "SSH-", 4) == 0) {
				unsigned cp = linelen < sizeof(c->cli_ver) - 1
				              ? linelen : sizeof(c->cli_ver) - 1;
				memcpy(c->cli_ver, c->ib, cp);
				c->cli_ver[cp] = 0;
				c->cli_ver_len = cp;
				c->state = SSH_ST_EXPECT_KEXINIT;
			}
			ib_consume(c, i + 1);
			return 1;             /* keep scanning if it was a pre-banner line */
		}
		if (i > 300) { fail(c, "version line too long"); return -1; }
	}
	return 0;
}

/* consume one binary packet (encrypted or not); 1 = progressed, 0 = need more */
static int try_packet(ssh_conn *c)
{
	unsigned pkt_len, need, payload_len, padlen;

	if (!c->recv_encrypted) {
		if (c->ib_len < 4) return 0;
		pkt_len = rd_u32(c->ib);
		if (pkt_len < 1 || pkt_len + 4 > SSH_IB_SZ) {
			fail(c, "packet too large"); return -1;
		}
		need = 4 + pkt_len;
		if (c->ib_len < need) return 0;
		padlen = c->ib[4];
		if ((unsigned)padlen + 1 > pkt_len) { fail(c, "bad padding"); return -1; }
		payload_len = pkt_len - 1 - padlen;
		handle_packet(c, c->ib + 5, payload_len);
		ib_consume(c, need);
		c->recv_seq++;
		return 1;
	} else {
		uint8_t *k_main   = c->ek_c2s;
		uint8_t *k_header = c->ek_c2s + 32;
		uint8_t nonce[8], lenbuf[4], polykey[32], tag[16];

		if (c->ib_len < 4) return 0;
		seqbuf8(c->recv_seq, nonce);
		dossh_chacha20_djb(lenbuf, c->ib, 4, k_header, nonce, 0);
		pkt_len = rd_u32(lenbuf);
		if (pkt_len < 8 || pkt_len % 8 != 0 || 4 + pkt_len + 16 > SSH_IB_SZ) {
			fail(c, "bad encrypted length"); return -1;
		}
		need = 4 + pkt_len + 16;
		if (c->ib_len < need) return 0;

		dossh_chacha20_djb(polykey, (const uint8_t *)0, 32, k_main, nonce, 0);
		dossh_poly1305(tag, c->ib, 4 + pkt_len, polykey);
		if (memcmp(tag, c->ib + 4 + pkt_len, 16) != 0) {
			fail(c, "MAC verification failed"); return -1;
		}
		dossh_chacha20_djb(c->ib + 4, c->ib + 4, pkt_len, k_main, nonce, 1);
		padlen = c->ib[4];
		if ((unsigned)padlen + 1 > pkt_len) { fail(c, "bad padding"); return -1; }
		payload_len = pkt_len - 1 - padlen;
		handle_packet(c, c->ib + 5, payload_len);
		ib_consume(c, need);
		c->recv_seq++;
		return 1;
	}
}

/* ---- public API ----------------------------------------------------- */

void DOSSH_FAR ssh_reset(ssh_conn *c, const uint8_t hostkey_sk[64],
                         const uint8_t hostkey_pk[32])
{
	memset(c, 0, sizeof(*c));
	memcpy(c->hostkey_sk, hostkey_sk, 64);
	memcpy(c->hostkey_pk, hostkey_pk, 32);
	c->state = SSH_ST_VERSION;

	ob_append(c, (const uint8_t *)SERVER_ID_CRLF,
	          (unsigned)strlen(SERVER_ID_CRLF));
	build_our_kexinit(c);
	send_unenc(c, c->i_s, c->i_s_len);
}

int DOSSH_FAR ssh_input(ssh_conn *c, const uint8_t *data, unsigned n)
{
	if (c->state == SSH_ST_ERROR) return -1;
	if (c->ib_len + n > SSH_IB_SZ) { fail(c, "input overflow"); return -1; }
	if (n) { memcpy(c->ib + c->ib_len, data, n); c->ib_len += n; }

	while (c->state != SSH_ST_ERROR && c->state != SSH_ST_CLOSED) {
		int r = (c->state == SSH_ST_VERSION) ? try_version(c)
		                                     : try_packet(c);
		if (r <= 0) break;
	}
	return (c->state == SSH_ST_ERROR) ? -1 : 0;
}

unsigned DOSSH_FAR ssh_output(ssh_conn *c, uint8_t *buf, unsigned max)
{
	unsigned n = c->ob_len < max ? c->ob_len : max;
	if (n) {
		memcpy(buf, c->ob, n);
		if (n < c->ob_len) memmove(c->ob, c->ob + n, c->ob_len - n);
		c->ob_len -= n;
	}
	return n;
}

int DOSSH_FAR ssh_done(ssh_conn *c)   { return c->done; }
int DOSSH_FAR ssh_failed(ssh_conn *c) { return c->state == SSH_ST_ERROR; }

const char * DOSSH_FAR ssh_state_name(ssh_conn *c)
{
	switch (c->state) {
	case SSH_ST_VERSION:                return "VERSION";
	case SSH_ST_EXPECT_KEXINIT:         return "EXPECT_KEXINIT";
	case SSH_ST_EXPECT_ECDH_INIT:       return "EXPECT_ECDH_INIT";
	case SSH_ST_EXPECT_CLIENT_NEWKEYS:  return "EXPECT_CLIENT_NEWKEYS";
	case SSH_ST_EXPECT_SERVICE_REQUEST: return "EXPECT_SERVICE_REQUEST";
	case SSH_ST_AUTH:                   return "AUTH";
	case SSH_ST_SESSION:                return "SESSION";
	case SSH_ST_CLOSED:                 return "CLOSED";
	case SSH_ST_ERROR:                  return "ERROR";
	default:                            return "?";
	}
}

/* ---- userauth + session channel byte interface --------------------- */

void DOSSH_FAR ssh_set_password(ssh_conn *c, const char *pw)
{
	unsigned k = 0;
	if (pw)
		while (pw[k] && k < sizeof(c->password) - 1) { c->password[k] = pw[k]; k++; }
	c->password[k] = 0;
	c->have_password = (k > 0);
}

void DOSSH_FAR ssh_set_authorized_keys(ssh_conn *c, const uint8_t *keys,
                                       unsigned count)
{
	c->authkeys = keys;                 /* [count][32] ed25519 public keys */
	c->authkey_count = count;
}

/* base64 value of one character, or -1 if it is not a base64 digit */
static int b64val(int ch)
{
	if (ch >= 'A' && ch <= 'Z') return ch - 'A';
	if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
	if (ch >= '0' && ch <= '9') return ch - '0' + 52;
	if (ch == '+') return 62;
	if (ch == '/') return 63;
	return -1;
}

/* Decode base64 (no embedded whitespace, optional trailing '=' padding) into
 * out[0..outmax). Returns the number of bytes decoded, or 0 on any malformed
 * input / overflow. */
static unsigned b64_decode(const char *in, unsigned inlen,
                           uint8_t *out, unsigned outmax)
{
	unsigned i = 0, o = 0;
	while (inlen && in[inlen - 1] == '=') inlen--;   /* drop pad from the view */
	while (i < inlen) {
		unsigned rem = inlen - i;
		int c0 = b64val(in[i]);
		int c1 = (rem > 1) ? b64val(in[i + 1]) : -1;
		int c2 = (rem > 2) ? b64val(in[i + 2]) : -1;
		int c3 = (rem > 3) ? b64val(in[i + 3]) : -1;
		if (c0 < 0 || c1 < 0) return 0;              /* a lone trailing char */
		if (o >= outmax) return 0;
		out[o++] = (uint8_t)((c0 << 2) | (c1 >> 4));
		if (rem == 2) break;
		if (c2 < 0) return 0;
		if (o >= outmax) return 0;
		out[o++] = (uint8_t)((c1 << 4) | (c2 >> 2));
		if (rem == 3) break;
		if (c3 < 0) return 0;
		if (o >= outmax) return 0;
		out[o++] = (uint8_t)((c2 << 6) | c3);
		i += 4;
	}
	return o;
}

int DOSSH_FAR ssh_parse_authkey_line(const char *line, uint8_t pubkey[32])
{
	const char *p = line;
	const char *b64;
	unsigned b64len = 0;
	uint8_t blob[80];                    /* an ssh-ed25519 blob is 51 bytes */
	unsigned bloblen;
	const uint8_t *key;

	while (*p == ' ' || *p == '\t') p++;             /* leading whitespace */
	if (*p == 0 || *p == '#' || *p == '\r' || *p == '\n') return 0;  /* blank/comment */

	/* must be "ssh-ed25519" followed by whitespace (ssh-ed25519 only) */
	if (strlen(p) < 11 || memcmp(p, "ssh-ed25519", 11) != 0) return 0;
	p += 11;
	if (*p != ' ' && *p != '\t') return 0;
	while (*p == ' ' || *p == '\t') p++;

	b64 = p;                                          /* the base64 key blob */
	while (b64val(*p) >= 0 || *p == '=') { p++; b64len++; }

	bloblen = b64_decode(b64, b64len, blob, sizeof(blob));
	key = ed25519_key_from_blob(blob, bloblen);       /* validates the shape */
	if (!key) return 0;
	memcpy(pubkey, key, 32);
	return 1;
}

int DOSSH_FAR ssh_authenticated(ssh_conn *c) { return c->authenticated; }

int DOSSH_FAR ssh_channel_ready(ssh_conn *c)
{
	return c->chan_open && c->shell_ready && !c->chan_closed;
}

int DOSSH_FAR ssh_channel_getc(ssh_conn *c)
{
	int b;
	if (c->cin_head == c->cin_tail) return -1;
	b = c->cin[c->cin_head];
	c->cin_head = (c->cin_head + 1) % SSH_CIN_SZ;
	return b;
}

int DOSSH_FAR ssh_channel_putc(ssh_conn *c, int byte)
{
	if (!c->shell_ready || c->chan_closed) return 0;
	if (c->cout_len >= SSH_COUT_SZ)         return 0;   /* staging buffer full */
	c->cout[c->cout_len++] = (uint8_t)byte;
	return 1;
}

void DOSSH_FAR ssh_channel_flush(ssh_conn *c)
{
	unsigned sent = 0;

	if (!c->chan_open || c->chan_closed) { c->cout_len = 0; return; }

	while (sent < c->cout_len) {
		uint8_t pkt[9 + SSH_CHAN_CHUNK];
		unsigned take = c->cout_len - sent, o;

		if (take > SSH_CHAN_CHUNK)   take = SSH_CHAN_CHUNK;
		if (take > c->peer_window)   take = c->peer_window;
		if (take > c->peer_maxpkt)   take = c->peer_maxpkt;
		if (take == 0) break;                       /* window exhausted */
		/* leave room in the drain buffer so send_enc never overflows */
		if (c->ob_len + take + 64 > SSH_OB_SZ) break;

		o = 0;
		pkt[o++] = MSG_CHANNEL_DATA;
		put_u32(pkt + o, c->peer_chan); o += 4;
		o += put_str(pkt + o, c->cout + sent, take);
		send_packet(c, pkt, o);
		if (c->state == SSH_ST_ERROR) break;
		c->peer_window -= take;
		sent += take;
	}

	if (sent) {
		if (sent >= c->cout_len) c->cout_len = 0;
		else { memmove(c->cout, c->cout + sent, c->cout_len - sent);
		       c->cout_len -= sent; }
	}
}

void DOSSH_FAR ssh_winsize(ssh_conn *c, int *cols, int *rows)
{
	if (cols) *cols = c->term_cols ? (int)c->term_cols : 80;
	if (rows) *rows = c->term_rows ? (int)c->term_rows : 25;
}

int DOSSH_FAR ssh_channel_eof(ssh_conn *c) { return c->chan_eof; }

void DOSSH_FAR ssh_channel_close(ssh_conn *c)
{
	uint8_t p[32];
	unsigned o;

	if (!c->chan_open || c->chan_sent_close) return;
	ssh_channel_flush(c);                            /* push any staged bytes */

	/* a clean logout: report exit-status 0 so the client exits 0 (RFC 4254
	 * sec 6.10). Only meaningful once a shell/exec was actually granted. */
	if (c->shell_ready) {
		o = 0;
		p[o++] = MSG_CHANNEL_REQUEST;
		put_u32(p + o, c->peer_chan); o += 4;
		o += put_str(p + o, (const uint8_t *)"exit-status", 11);
		p[o++] = 0;                                  /* want_reply = FALSE */
		put_u32(p + o, 0); o += 4;                   /* exit status 0       */
		send_packet(c, p, o);
	}

	if (!c->chan_sent_eof) {
		p[0] = MSG_CHANNEL_EOF;
		put_u32(p + 1, c->peer_chan);
		send_packet(c, p, 5);
		c->chan_sent_eof = 1;
	}
	p[0] = MSG_CHANNEL_CLOSE;
	put_u32(p + 1, c->peer_chan);
	send_packet(c, p, 5);
	c->chan_sent_close = 1;
	c->chan_closed = 1;
}

int DOSSH_FAR ssh_channel_closed(ssh_conn *c) { return c->chan_closed; }
