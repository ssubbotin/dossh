/*
 * telnet.c - minimal telnet server glue (see telnet.h).
 *
 * One IAC state machine per client slot: DOSSH serves up to NCONN connections
 * that share one screen but negotiate independently. The negotiation replies and
 * the opening hello are unicast to a single slot; decoded keystrokes are handed
 * to the shared key mapper (ansi_key_byte), so all clients drive the one machine.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include "telnet.h"
#include "net.h"

extern int  net_tx_putc_slot( int i, int c );/* net.c: queue a byte to one slot */
extern void ansi_key_byte( unsigned char b );/* ansikey.c: map a keystroke byte */

/* telnet commands */
#define IAC   255
#define SE    240
#define SB    250
#define WILL  251
#define WONT  252
#define DO    253
#define DONT  254
/* options we care about */
#define OPT_BINARY 0
#define OPT_ECHO   1
#define OPT_SGA    3

/* inbound IAC state machine, per slot: iac = 0 data, 1 IAC, 2 verb, 3 SB,
 * 4 SB+IAC. willed/doed track which options we have already asserted (bit per
 * option) so a client's reply is not answered again (loop-free). */
static int           iac[NCONN];
static unsigned char verb[NCONN];
static unsigned char willed[NCONN], doed[NCONN];

static void put3( int i, unsigned char a, unsigned char b, unsigned char c )
{
    net_tx_putc_slot( i, a ); net_tx_putc_slot( i, b ); net_tx_putc_slot( i, c );
}

void telnet_reset( int i )
{
    iac[i] = 0; willed[i] = 0; doed[i] = 0;
}

void telnet_hello( int i )
{
    put3( i, IAC, WILL, OPT_ECHO );   /* we echo (client: stop local echo)   */
    put3( i, IAC, WILL, OPT_SGA );    /* suppress go-ahead -> char mode      */
    put3( i, IAC, DO,   OPT_SGA );
    put3( i, IAC, WILL, OPT_BINARY ); /* 8-bit clean both ways               */
    put3( i, IAC, DO,   OPT_BINARY );
    willed[i] = (1 << OPT_ECHO) | (1 << OPT_SGA) | (1 << OPT_BINARY);
    doed[i]   = (1 << OPT_SGA) | (1 << OPT_BINARY);
}

/* answer inbound negotiation once per option, never re-asserting what we
   already offered (which would ping-pong with the client's replies) */
static int ours( unsigned char opt )
{
    return opt == OPT_ECHO || opt == OPT_SGA || opt == OPT_BINARY;
}
static void respond( int i, unsigned char v, unsigned char opt )
{
    unsigned char bit = ( opt < 8 ) ? (unsigned char)( 1 << opt ) : 0;
    if( v == DO ) {                        /* client: please WILL opt */
        if( ours( opt ) ) { if( !( willed[i] & bit ) ) { put3( i, IAC, WILL, opt ); willed[i] |= bit; } }
        else put3( i, IAC, WONT, opt );
    } else if( v == WILL ) {               /* client: I WILL opt */
        if( opt == OPT_SGA || opt == OPT_BINARY ) { if( !( doed[i] & bit ) ) { put3( i, IAC, DO, opt ); doed[i] |= bit; } }
        else put3( i, IAC, DONT, opt );
    } else if( v == WONT ) {
        put3( i, IAC, DONT, opt );
    } else if( v == DONT ) {
        put3( i, IAC, WONT, opt );
    }
}

void telnet_in( int i, unsigned char b )
{
    switch( iac[i] ) {
    case 0:
        if( b == IAC ) { iac[i] = 1; return; }
        ansi_key_byte( b );
        return;
    case 1:                                /* after IAC */
        if( b == IAC ) { ansi_key_byte( IAC ); iac[i] = 0; return; }  /* literal FF */
        if( b == SB )  { iac[i] = 3; return; }
        if( b >= WILL && b <= DONT ) { verb[i] = b; iac[i] = 2; return; }
        iac[i] = 0; return;                /* IAC <other>: 2-byte, ignore */
    case 2:                                /* verb + option */
        respond( i, verb[i], b );
        iac[i] = 0; return;
    case 3:                                /* inside SB: wait for IAC SE */
        if( b == IAC ) iac[i] = 4;
        return;
    case 4:
        iac[i] = ( b == SE ) ? 0 : 3;      /* SE ends the subnegotiation */
        return;
    }
}
