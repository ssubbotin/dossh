/*
 * net.c - DOSSH network transport: a small ARP/IP/TCP stack over a DOS
 *         packet driver, presented to the framing code as a byte stream.
 *
 * Scope is deliberately tiny: one static IP, one listening TCP port, one
 * active connection. Reliability for the interactive stream comes from TCP,
 * which also lets the packet receiver stay a single-buffer, drop-tolerant
 * stub (a lost inbound segment is simply retransmitted).
 *
 * Replies reuse the source MAC of the frame that prompted them (the SLIRP /
 * gateway MAC), so the stack never needs to originate ARP.
 *
 * DOSSHD services the network from the timer ISR, i.e. calls send_pkt at
 * interrupt time. Two things make that work: (1) a NIC whose driver does a
 * blind, fire-and-forget transmit - AMD PCnet (PCNTPK.COM), a bus-master DMA
 * hand-off, unlike the NE2000's shared programmed-DMA send which corrupts at
 * interrupt time; and (2) issuing send_pkt on a private stack (pktrecv.asm's
 * pkt_send_bigstack) - the driver's send needs a real stack, and the tiny
 * interrupted DOS stack silently fails it. See docs/DESIGN.md sec 13.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <dos.h>
#include <i86.h>
#include <string.h>
#include "net.h"

/* ---- identity + counters --------------------------------------------- */
unsigned char g_mac[6];
unsigned char g_ip[4];
unsigned long g_rx_frames, g_arp_replies, g_tcp_segs;

static unsigned char pkt_int;      /* packet-driver software interrupt */
static unsigned      pkt_handle;
static unsigned      my_port;

/*
 * Single-stage receive buffer + the packet-driver receiver, both defined in
 * pktrecv.asm. The driver calls pkt_receiver with a FAR call:
 *   AX=0 -> it returns ES:DI = &pkt_stage for the frame to be copied into
 *   AX=1 -> the frame is in pkt_stage (CX bytes); it sets pkt_flag for us
 * The driver serialises the two calls, so one buffer is safe; a second frame
 * arriving before net_poll drains it is dropped - and, for TCP, retransmitted.
 */
extern unsigned char     pkt_stage[];
extern volatile unsigned pkt_len;
extern volatile unsigned pkt_flag;
extern void __far        pkt_receiver( void );

/* ---- packet-driver API (invoked at the discovered software interrupt) - */

static int pkt_find( void )
{
    unsigned v;
    for( v = 0x60; v <= 0x7E; v++ ) {
        unsigned char __far *h = (unsigned char __far *)_dos_getvect( v );
        if( h != 0 && _fmemcmp( h + 3, "PKT DRVR", 8 ) == 0 ) {
            pkt_int = (unsigned char)v;
            return 1;
        }
    }
    return 0;
}

static int pkt_access( void )
{
    union REGS r;
    struct SREGS s;
    void __far *rcv = (void __far *)pkt_receiver;

    segread( &s );
    r.h.ah = 0x02;             /* access_type            */
    r.h.al = 0x01;             /* class 1 = Ethernet     */
    r.x.bx = 0xFFFF;           /* any interface type     */
    r.h.dl = 0x00;             /* interface number 0     */
    r.x.cx = 0x0000;           /* type length 0 = all packet types */
    r.x.si = 0;                /* DS:SI = type (unused)  */
    r.x.di = FP_OFF( rcv );    /* ES:DI = receiver       */
    s.es   = FP_SEG( rcv );
    int86x( pkt_int, &r, &r, &s );
    if( r.x.cflag )
        return 0;
    pkt_handle = r.x.ax;
    return 1;
}

static void pkt_get_address( void )
{
    union REGS r;
    struct SREGS s;
    void __far *mac = (void __far *)g_mac;

    segread( &s );
    r.h.ah = 0x06;             /* get_address            */
    r.x.bx = pkt_handle;
    r.x.di = FP_OFF( mac );
    s.es   = FP_SEG( mac );
    r.x.cx = 6;
    int86x( pkt_int, &r, &r, &s );
}

unsigned char g_txbuf[1600];   /* in DGROUP; pktrecv.asm sends DS:SI from here */

/* pktrecv.asm: send_pkt on a private stack (see there). Params/result: */
extern void            pkt_send_bigstack( void );
extern volatile unsigned char sc_int;
extern volatile unsigned      sc_bufoff;
extern volatile unsigned      sc_len;
extern volatile unsigned char sc_cf;

static void pkt_send( unsigned len )
{
    void __far *buf = (void __far *)g_txbuf;

    sc_int    = pkt_int;
    sc_bufoff = FP_OFF( buf );
    sc_len    = len;
    pkt_send_bigstack();       /* send_pkt AH=4 on a private stack, IF=0 */
}

static void pkt_release( void )
{
    union REGS r;
    r.h.ah = 0x03;             /* release_type           */
    r.x.bx = pkt_handle;
    int86( pkt_int, &r, &r );
}

/* ---- byte order + checksum ------------------------------------------- */

static unsigned rd16( unsigned char *p ) { return ((unsigned)p[0] << 8) | p[1]; }
static unsigned long rd32( unsigned char *p )
{
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16)
         | ((unsigned long)p[2] << 8)  |  (unsigned long)p[3];
}
static void wr16( unsigned char *p, unsigned v ) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void wr32( unsigned char *p, unsigned long v )
{
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16);
    p[2]=(unsigned char)(v>>8);  p[3]=(unsigned char)v;
}

static unsigned long sum16( unsigned char *p, unsigned n, unsigned long sum )
{
    unsigned i;
    for( i = 0; i + 1 < n; i += 2 )
        sum += ((unsigned long)p[i] << 8) | p[i + 1];
    if( n & 1 )
        sum += (unsigned long)p[n - 1] << 8;
    return sum;
}
static unsigned fin16( unsigned long sum )
{
    while( sum >> 16 )
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned)(~sum & 0xFFFF);
}

/* ---- frame layout offsets -------------------------------------------- */
#define ETH_HLEN 14
#define IP_OFF   ETH_HLEN
#define ET_ARP   0x0806
#define ET_IP    0x0800
#define IPP_TCP  6

/* ---- Ethernet / IP transmit ------------------------------------------ */

static unsigned g_ip_id;

/* build eth+ip header into g_txbuf, copy l4[0..l4len), send. dstmac/dstip
 * are the peer's, taken from the frame we are answering. */
static void ip_send( unsigned char proto, unsigned char *dstmac,
                     unsigned char *dstip, unsigned char *l4, unsigned l4len )
{
    unsigned char *e = g_txbuf;
    unsigned char *ip = g_txbuf + IP_OFF;
    unsigned tot = 20 + l4len;

    memcpy( e, dstmac, 6 );
    memcpy( e + 6, g_mac, 6 );
    wr16( e + 12, ET_IP );

    ip[0] = 0x45; ip[1] = 0x00;
    wr16( ip + 2, tot );
    wr16( ip + 4, ++g_ip_id );
    wr16( ip + 6, 0x4000 );       /* don't fragment */
    ip[8] = 64; ip[9] = proto;
    ip[10] = ip[11] = 0;
    memcpy( ip + 12, g_ip, 4 );
    memcpy( ip + 16, dstip, 4 );
    wr16( ip + 10, fin16( sum16( ip, 20, 0 ) ) );

    memcpy( ip + 20, l4, l4len );
    pkt_send( ETH_HLEN + tot );
}

/* ---- ARP ------------------------------------------------------------- */

static void arp_in( unsigned char *f, unsigned n )
{
    unsigned char *a = f + ETH_HLEN;
    static unsigned char reply[28];   /* static: runs in the ISR (SS != DS) */

    if( n < ETH_HLEN + 28 )        return;
    if( rd16( a ) != 0x0001 )      return;   /* htype Ethernet */
    if( rd16( a + 2 ) != ET_IP )   return;   /* ptype IPv4     */
    if( rd16( a + 6 ) != 0x0001 )  return;   /* op request     */
    if( memcmp( a + 24, g_ip, 4 ) != 0 ) return;   /* target = us */

    /* build a reply: op=2, sender=us, target=the requester */
    memcpy( reply, a, 28 );
    wr16( reply + 6, 0x0002 );
    memcpy( reply + 8, g_mac, 6 );          /* sender HW  = us   */
    memcpy( reply + 14, g_ip, 4 );          /* sender IP  = us   */
    memcpy( reply + 18, a + 8, 6 );         /* target HW  = them */
    memcpy( reply + 24, a + 14, 4 );        /* target IP  = them */

    /* Ethernet frame straight into g_txbuf (ARP is not IP) */
    memcpy( g_txbuf, a + 8, 6 );            /* dst = requester MAC */
    memcpy( g_txbuf + 6, g_mac, 6 );
    wr16( g_txbuf + 12, ET_ARP );
    memcpy( g_txbuf + ETH_HLEN, reply, 28 );
    pkt_send( ETH_HLEN + 28 );
    g_arp_replies++;
}

/* ---- TCP ------------------------------------------------------------- */

#define TS_LISTEN   0
#define TS_SYNRCVD  1
#define TS_ESTAB    2

#define SND_SZ   8192
#define SND_MASK (SND_SZ - 1)
#define RCV_SZ   512
#define RCV_MASK (RCV_SZ - 1)
#define MSS_TX   1400
#define REXMIT_TICKS 9          /* ~0.5s at 18.2 Hz */

static unsigned char tstate;
static unsigned char peer_mac[6], peer_ip[4];
static unsigned      peer_port;
static unsigned long snd_una, snd_nxt;
static unsigned long rcv_nxt;
static unsigned char sbuf[SND_SZ];
static unsigned      s_una, s_nxt, s_end;
static unsigned char rbuf[RCV_SZ];
static unsigned      r_head, r_tail;
static unsigned long rexmit_at;
static unsigned      rexmit_count;     /* consecutive retransmits w/o progress */

#define MAX_REXMIT 24          /* ~13s of no ACK -> peer is dead, re-LISTEN */

static unsigned long ticks( void )
{
    return *(unsigned long __far *)MK_FP( 0x40, 0x6C );
}

static void tcp_reset_listen( void )
{
    tstate = TS_LISTEN;
    s_una = s_nxt = s_end = 0;
    r_head = r_tail = 0;
    rexmit_count = 0;
}

/* send one TCP segment: flags, seq/ack from state, optional MSS option,
 * optional payload of dlen bytes starting at buffer index doff. */
static void tcp_send_seg( unsigned char flags, int with_mss,
                          unsigned doff, unsigned dlen )
{
    static unsigned char seg[20 + 4 + MSS_TX];   /* static: runs in the ISR */
    unsigned hlen = with_mss ? 24 : 20;
    unsigned i;
    unsigned long sum;

    wr16( seg + 0, my_port );
    wr16( seg + 2, peer_port );
    wr32( seg + 4, snd_nxt );
    wr32( seg + 8, rcv_nxt );
    seg[12] = (unsigned char)((hlen / 4) << 4);
    seg[13] = flags;
    /* advertise the real free space so the peer never overruns the ring */
    wr16( seg + 14, (RCV_SZ - 1) - ((r_head - r_tail) & RCV_MASK) );
    seg[16] = seg[17] = 0;          /* checksum (filled below) */
    seg[18] = seg[19] = 0;          /* urgent */
    if( with_mss ) {
        seg[20] = 0x02; seg[21] = 0x04;   /* MSS option */
        wr16( seg + 22, MSS_TX );
    }
    for( i = 0; i < dlen; i++ )
        seg[hlen + i] = sbuf[(doff + i) & SND_MASK];

    /* checksum over pseudo-header + segment */
    sum = sum16( g_ip, 4, 0 );
    sum = sum16( peer_ip, 4, sum );
    sum += IPP_TCP;
    sum += hlen + dlen;
    sum = sum16( seg, hlen + dlen, sum );
    wr16( seg + 16, fin16( sum ) );

    ip_send( IPP_TCP, peer_mac, peer_ip, seg, hlen + dlen );
    g_tcp_segs++;
}

/* transmit any buffered, not-yet-sent bytes as data segments */
static void tcp_output( void )
{
    unsigned unsent;

    if( tstate != TS_ESTAB )
        return;
    unsent = (s_end - s_nxt) & SND_MASK;
    while( unsent ) {
        unsigned n = unsent > MSS_TX ? MSS_TX : unsent;
        tcp_send_seg( 0x18, 0, s_nxt, n );    /* PSH|ACK */
        if( snd_una == snd_nxt )              /* first unacked byte: arm timer */
            rexmit_at = ticks() + REXMIT_TICKS;
        s_nxt = (s_nxt + n) & SND_MASK;
        snd_nxt += n;
        unsent -= n;
    }
}

static void tcp_in( unsigned char *f, unsigned n )
{
    unsigned char *ip = f + IP_OFF;
    unsigned ihl = (ip[0] & 0x0F) * 4;
    unsigned char *t = ip + ihl;
    unsigned tcplen = rd16( ip + 2 ) - ihl;
    unsigned toff = (t[12] >> 4) * 4;
    unsigned char flags = t[13];
    unsigned sport = rd16( t );
    unsigned dport = rd16( t + 2 );
    unsigned long seq = rd32( t + 4 );
    unsigned long ack = rd32( t + 8 );
    unsigned dlen;

    if( dport != my_port )
        return;
    if( tcplen < toff )
        return;
    dlen = tcplen - toff;

    if( flags & 0x04 ) {                       /* RST */
        tcp_reset_listen();
        return;
    }

    /* A SYN from our peer's host while we are ESTABlished means the old client
       is gone (an unclean drop leaves no FIN/RST) and it is reconnecting from a
       new ephemeral port - drop the stale peer and set the new connection up
       below. Gated on source IP so a stray/scanner SYN can't kill the session. */
    if( (flags & 0x02) && tstate == TS_ESTAB
                       && memcmp( ip + 12, peer_ip, 4 ) == 0 )
        tcp_reset_listen();

    if( tstate == TS_LISTEN ) {
        if( !(flags & 0x02) )                  /* want SYN */
            return;
        memcpy( peer_mac, f + 6, 6 );
        memcpy( peer_ip, ip + 12, 4 );
        peer_port = sport;
        snd_una = snd_nxt = 0x00013700UL + ticks();
        rcv_nxt = seq + 1;
        tstate = TS_SYNRCVD;
        s_una = s_nxt = s_end = 0;
        r_head = r_tail = 0;
        tcp_send_seg( 0x12, 1, 0, 0 );         /* SYN|ACK + MSS */
        snd_nxt += 1;                          /* SYN consumes a seq */
        rexmit_at = ticks() + REXMIT_TICKS;
        return;
    }

    /* must be our peer */
    if( sport != peer_port || memcmp( ip + 12, peer_ip, 4 ) != 0 )
        return;

    if( tstate == TS_SYNRCVD ) {
        if( (flags & 0x10) && ack == snd_nxt ) {   /* ACK of our SYN */
            snd_una = ack;
            tstate = TS_ESTAB;
            rexmit_count = 0;                  /* fresh budget for the first data */
        } else
            return;
    }

    if( tstate != TS_ESTAB )
        return;

    if( flags & 0x10 ) {                       /* ACK: advance send window */
        if( (long)(ack - snd_una) > 0 && (long)(ack - snd_nxt) <= 0 ) {
            unsigned freed = (unsigned)(ack - snd_una);
            s_una = (s_una + freed) & SND_MASK;
            snd_una = ack;
            rexmit_at = ticks() + REXMIT_TICKS;
            rexmit_count = 0;                  /* peer is alive and making progress */
        }
    }

    if( dlen ) {
        if( seq == rcv_nxt ) {                 /* in-order data: keys */
            unsigned i, stored = 0;
            for( i = 0; i < dlen; i++ ) {
                unsigned nh = (r_head + 1) & RCV_MASK;
                if( nh == r_tail )             /* ring full: keep the rest */
                    break;                     /* ... unacked, so it retransmits */
                rbuf[r_head] = t[toff + i];
                r_head = nh;
                stored++;
            }
            rcv_nxt += stored;                 /* only ack bytes we actually kept */
        }
        tcp_send_seg( 0x10, 0, 0, 0 );         /* ACK (also re-ACKs on gap) */
    }

    if( flags & 0x01 ) {                       /* FIN: ack and reopen */
        rcv_nxt += 1;
        tcp_send_seg( 0x10, 0, 0, 0 );
        tcp_reset_listen();
    }
}

static void tcp_timer( void )
{
    if( tstate < TS_SYNRCVD )
        return;
    if( (long)(snd_nxt - snd_una) > 0 && (long)(ticks() - rexmit_at) >= 0 ) {
        if( ++rexmit_count > MAX_REXMIT ) {    /* peer stopped ACKing: give up */
            tcp_reset_listen();                /* ... and free up for a reconnect */
            return;
        }
        /* go-back-N: resend from the oldest unacked byte */
        s_nxt = s_una;
        snd_nxt = snd_una;
        if( tstate == TS_SYNRCVD )
            tcp_send_seg( 0x12, 1, 0, 0 );     /* resend SYN|ACK */
        rexmit_at = ticks() + REXMIT_TICKS;
    }
}

/* ---- IP dispatch + poll ---------------------------------------------- */

static void handle_frame( unsigned char *f, unsigned n )
{
    unsigned et;

    if( n < ETH_HLEN ) return;
    et = rd16( f + 12 );
    if( et == ET_ARP ) {
        arp_in( f, n );
        return;
    }
    if( et != ET_IP ) return;
    if( n < IP_OFF + 20 ) return;
    if( (f[IP_OFF] >> 4) != 4 ) return;        /* IPv4 */
    if( memcmp( f + IP_OFF + 16, g_ip, 4 ) != 0 ) return;   /* to us */

    if( f[IP_OFF + 9] == IPP_TCP )
        tcp_in( f, n );
}

void net_poll( void )
{
    static unsigned char work[1600];
    unsigned flen = 0;

    tcp_timer();

    if( pkt_flag ) {
        _disable();
        flen = pkt_len;
        if( flen > sizeof( work ) ) flen = sizeof( work );
        memcpy( work, pkt_stage, flen );
        pkt_flag = 0;
        _enable();
        g_rx_frames++;
        handle_frame( work, flen );
    }
    tcp_output();
}

/* ---- link API for the framing code ----------------------------------- */

int net_connected( void ) { return tstate == TS_ESTAB; }

int net_tx_putc( int c )
{
    unsigned used = (s_end - s_una) & SND_MASK;
    if( used >= SND_SZ - 1 )
        return 0;
    sbuf[s_end] = (unsigned char)c;
    s_end = (s_end + 1) & SND_MASK;
    return 1;
}

void net_tx_flush( void ) { tcp_output(); }

int net_rx_getc( void )
{
    int c;
    if( r_tail == r_head )
        return -1;
    c = rbuf[r_tail];
    r_tail = (r_tail + 1) & RCV_MASK;
    return c;
}

/* ---- lifecycle ------------------------------------------------------- */

int net_open( unsigned char a, unsigned char b, unsigned char c,
              unsigned char d, unsigned port )
{
    g_ip[0] = a; g_ip[1] = b; g_ip[2] = c; g_ip[3] = d;
    my_port = port;
    pkt_flag = 0;
    tcp_reset_listen();
    if( !pkt_find() )   return 0;
    if( !pkt_access() ) return 0;
    pkt_get_address();
    return 1;
}

void net_close( void )
{
    if( pkt_int )
        pkt_release();
}

/* the resident driver identity, so a separate transient DOSSHD /U can release
 * our receiver from the driver (it cannot reach these statics otherwise) */
unsigned char net_pkt_int( void )    { return pkt_int; }
unsigned      net_pkt_handle( void ) { return pkt_handle; }

void net_release( unsigned char int_no, unsigned handle )
{
    union REGS r;
    r.h.ah = 0x03;             /* release_type */
    r.x.bx = handle;
    int86( int_no, &r, &r );
}

