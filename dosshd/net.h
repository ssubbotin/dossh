/*
 * net.h - DOSSH network transport: TCP over a DOS packet driver.
 *
 * A tiny, purpose-built ARP/IP/TCP stack (single listening socket, up to NCONN
 * simultaneous connections) over the Crynwr packet-driver interface, presented
 * to the framing code as the same byte-stream `link` the serial path uses. The
 * screen mirror is broadcast to every client; their keystrokes are merged.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_NET_H
#define DOSSH_NET_H

/* Maximum simultaneous TCP clients. DOSSH mirrors one shared screen stream to
 * all of them and merges their keystrokes. Bounded by DGROUP: each slot carries
 * a SND_SZ send ring. telnet.c keeps a parallel per-slot IAC state array. */
#define NCONN 3

/* our identity, filled by net_open() */
extern unsigned char g_mac[6];
extern unsigned char g_ip[4];

/* observability counters */
extern unsigned long g_rx_frames;
extern unsigned long g_arp_replies;
extern unsigned long g_tcp_segs;

/* bring the stack up: find the packet driver, register a receiver, learn our
 * MAC, adopt the given static IP and TCP listen port. Returns 0 on failure. */
int  net_open( unsigned char ip0, unsigned char ip1,
               unsigned char ip2, unsigned char ip3, unsigned port );

/* service the stack: drain the RX ring, run ARP/IP/UDP/TCP, time retransmits.
 * Call frequently (from the timer tick). DOS-call-free. */
void net_poll( void );

/* release the packet-driver handle (call before exit if not staying resident) */
void net_close( void );

/* resident driver identity + an explicit release, so a separate transient
 * DOSSHD /U can unregister the resident receiver from the packet driver */
unsigned char net_pkt_int( void );
unsigned      net_pkt_handle( void );
void          net_release( unsigned char int_no, unsigned handle );

/* byte-stream link API over up to NCONN TCP connections. The screen mirror is
 * broadcast to every client; keystrokes from all clients are merged. */
int  net_connected( void );        /* 1 if any client TCP session is ESTABLISHED */
int  net_slots( void );            /* number of connection slots (NCONN)          */
int  net_take_new_slot( void );    /* index of a just-connected slot, else -1     */
int  net_tx_putc( int c );         /* broadcast a byte to all clients; 0 if any is full */
int  net_tx_putc_slot( int i, int c ); /* unicast a byte to one slot; 0 if full   */
void net_tx_flush( void );         /* push queued bytes out as TCP segments        */
int  net_rx_getc( int i );         /* next byte received from slot i, or -1        */

#endif
