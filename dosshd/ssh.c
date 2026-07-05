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

/* SSH message numbers (RFC 4253 sec 12, RFC 5656). */
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
	c->done = 1;

	/* optional courtesy reply (also proves our encrypt path): SERVICE_ACCEPT */
	o = 0;
	accept[o++] = MSG_SERVICE_ACCEPT;
	o += put_str(accept + o, (const uint8_t *)c->svc_name, slen);
	send_packet(c, accept, o);

	c->state = SSH_ST_DONE;
}

static void handle_packet(ssh_conn *c, const uint8_t *pl, unsigned plen)
{
	uint8_t msg = plen ? pl[0] : 0;

	/* messages allowed at any time */
	if (msg == MSG_DISCONNECT) { fail(c, "peer disconnect"); return; }
	if (msg == MSG_IGNORE || msg == MSG_DEBUG || msg == MSG_UNIMPLEMENTED)
		return;

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

	while (c->state != SSH_ST_ERROR && c->state != SSH_ST_DONE) {
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
	case SSH_ST_DONE:                   return "DONE";
	case SSH_ST_ERROR:                  return "ERROR";
	default:                            return "?";
	}
}
