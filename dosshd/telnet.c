/*
 * telnet.c - minimal telnet server glue (see telnet.h).
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include "telnet.h"

extern int  net_tx_putc( int c );            /* net.c: queue an outbound byte  */
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

/* inbound IAC state machine */
static int iac;                 /* 0 data, 1 IAC, 2 verb, 3 SB, 4 SB+IAC */
static unsigned char verb;
/* which options we've already asserted (so a client's reply is not answered
   again - loop-free): bit per option, for our WILL and our DO */
static unsigned char willed, doed;

static void put3( unsigned char a, unsigned char b, unsigned char c )
{
    net_tx_putc( a ); net_tx_putc( b ); net_tx_putc( c );
}

void telnet_reset( void )
{
    iac = 0; willed = 0; doed = 0;
}

void telnet_hello( void )
{
    put3( IAC, WILL, OPT_ECHO );      /* we echo (client: stop local echo)   */
    put3( IAC, WILL, OPT_SGA );       /* suppress go-ahead -> char mode      */
    put3( IAC, DO,   OPT_SGA );
    put3( IAC, WILL, OPT_BINARY );    /* 8-bit clean both ways               */
    put3( IAC, DO,   OPT_BINARY );
    willed = (1 << OPT_ECHO) | (1 << OPT_SGA) | (1 << OPT_BINARY);
    doed   = (1 << OPT_SGA) | (1 << OPT_BINARY);
}

/* answer inbound negotiation once per option, never re-asserting what we
   already offered (which would ping-pong with the client's replies) */
static int ours( unsigned char opt )
{
    return opt == OPT_ECHO || opt == OPT_SGA || opt == OPT_BINARY;
}
static void respond( unsigned char v, unsigned char opt )
{
    unsigned char bit = ( opt < 8 ) ? (unsigned char)( 1 << opt ) : 0;
    if( v == DO ) {                        /* client: please WILL opt */
        if( ours( opt ) ) { if( !( willed & bit ) ) { put3( IAC, WILL, opt ); willed |= bit; } }
        else put3( IAC, WONT, opt );
    } else if( v == WILL ) {               /* client: I WILL opt */
        if( opt == OPT_SGA || opt == OPT_BINARY ) { if( !( doed & bit ) ) { put3( IAC, DO, opt ); doed |= bit; } }
        else put3( IAC, DONT, opt );
    } else if( v == WONT ) {
        put3( IAC, DONT, opt );
    } else if( v == DONT ) {
        put3( IAC, WONT, opt );
    }
}

void telnet_in( unsigned char b )
{
    switch( iac ) {
    case 0:
        if( b == IAC ) { iac = 1; return; }
        ansi_key_byte( b );
        return;
    case 1:                                /* after IAC */
        if( b == IAC ) { ansi_key_byte( IAC ); iac = 0; return; }  /* literal FF */
        if( b == SB )  { iac = 3; return; }
        if( b >= WILL && b <= DONT ) { verb = b; iac = 2; return; }
        iac = 0; return;                   /* IAC <other>: 2-byte, ignore */
    case 2:                                /* verb + option */
        respond( verb, b );
        iac = 0; return;
    case 3:                                /* inside SB: wait for IAC SE */
        if( b == IAC ) iac = 4;
        return;
    case 4:
        iac = ( b == SE ) ? 0 : 3;         /* SE ends the subnegotiation */
        return;
    }
}
