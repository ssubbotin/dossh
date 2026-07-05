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
#include <string.h>

#include "telnet.h"
#include "net.h"

extern int  net_tx_putc_slot( int i, int c );/* net.c: queue a byte to one slot */
extern void ansi_key_byte( unsigned char b );/* ansikey.c: map a keystroke byte */
extern void render_reset( void );            /* render.c: force a full repaint  */
extern int  g_eof_exit;                      /* dosshd.c: /EOF opt-in Ctrl-D drop */

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
#define OPT_NAWS   31            /* RFC 1073: client reports its window size */

/* inbound IAC state machine, per slot: iac = 0 data, 1 IAC, 2 verb, 3 SB,
 * 4 SB+IAC. willed/doed track which options we have already asserted (bit per
 * option) so a client's reply is not answered again (loop-free). */
static int           iac[NCONN];
static unsigned char verb[NCONN];
static unsigned char willed[NCONN], doed[NCONN];

/* subnegotiation (IAC SB ... IAC SE) body collector + the last window size the
 * client reported via NAWS. The mirror is always a fixed 80x25 - we never
 * reflow to this; it only drives the auto-resize request and a repaint on a
 * genuine resize (the client may clear its screen when it changes size). */
static unsigned char sb_buf[NCONN][8];
static unsigned char sb_len[NCONN];
static unsigned      naws_w[NCONN], naws_h[NCONN];

/* --- authentication gate (network mode) -----------------------------------
 * If a password is configured (DOSSHD /NET ... /P:<pw>), a new client is held
 * at AU_PW: it is negotiated and prompted but NOT admitted to the broadcast
 * (net_slot_ready stays 0) and its keystrokes go to a per-slot collector rather
 * than the shared key mapper, until it sends the right password. With no
 * password every client is AU_OK and behaves exactly as before. The password
 * crosses the wire in cleartext (telnet), so it only means anything behind a
 * tunnel / VPN - see docs/SECURITY.md. */
#define AU_OK  0                 /* admitted: keystrokes drive the box */
#define AU_PW  1                 /* awaiting the password */
static char          g_password[32];         /* empty first byte = auth disabled */
static unsigned char au_state[NCONN];
static char          au_buf[NCONN][32];      /* password-so-far, per slot */
static unsigned char au_len[NCONN];
static unsigned char au_tries[NCONN];        /* failed attempts, per slot */

static void put3( int i, unsigned char a, unsigned char b, unsigned char c )
{
    net_tx_putc_slot( i, a ); net_tx_putc_slot( i, b ); net_tx_putc_slot( i, c );
}

static void telnet_reset( int i )
{
    iac[i] = 0; willed[i] = 0; doed[i] = 0;
    sb_len[i] = 0; naws_w[i] = 0; naws_h[i] = 0;
}

static void telnet_hello( int i )
{
    put3( i, IAC, WILL, OPT_ECHO );   /* we echo (client: stop local echo)   */
    put3( i, IAC, WILL, OPT_SGA );    /* suppress go-ahead -> char mode      */
    put3( i, IAC, DO,   OPT_SGA );
    put3( i, IAC, WILL, OPT_BINARY ); /* 8-bit clean both ways               */
    put3( i, IAC, DO,   OPT_BINARY );
    put3( i, IAC, DO,   OPT_NAWS );    /* please report your window size      */
    willed[i] = (1 << OPT_ECHO) | (1 << OPT_SGA) | (1 << OPT_BINARY);
    doed[i]   = (1 << OPT_SGA) | (1 << OPT_BINARY);
}

/* copy the configured password into resident DGROUP (called once, at install,
 * before going resident). An empty string disables the gate. */
void telnet_set_password( const char *pw )
{
    unsigned k = 0;
    while( pw[k] && k < sizeof( g_password ) - 1 ) {
        g_password[k] = pw[k];
        k++;
    }
    g_password[k] = 0;
}

static void au_say( int i, const char *s )
{
    while( *s )
        net_tx_putc_slot( i, (unsigned char)*s++ );
}

/* a full password line arrived (CR): admit the slot or reject it */
static void au_check( int i )
{
    au_buf[i][ au_len[i] ] = 0;
    if( strcmp( au_buf[i], g_password ) == 0 ) {
        au_state[i] = AU_OK;
        au_len[i] = 0;
        net_slot_ready( i, 1 );          /* admit this slot to the broadcast  */
        render_reset();                  /* full repaint: hand over the screen */
    } else {
        au_len[i] = 0;
        if( ++au_tries[i] >= 3 ) {
            au_say( i, "\r\nAccess denied.\r\n" );
            net_slot_drop( i );          /* three strikes: cut the session    */
        } else {
            au_say( i, "\r\nWrong password.\r\nPassword: " );
        }
    }
}

/* one decoded data byte (IAC already stripped): drive the box if this slot is
 * admitted, else feed the password collector - not echoed, so it stays hidden. */
static void feed_data( int i, unsigned char b )
{
    if( au_state[i] == AU_OK ) {
        if( g_eof_exit && b == 0x04 ) {  /* opt-in Ctrl-D: drop THIS client only  */
            net_slot_drop( i );          /* RST + re-LISTEN this slot (like au_check) */
            return;                      /* consume: never inject 0x04 into DOS   */
        }
        ansi_key_byte( b );
        return;
    }
    if( b == '\r' ) { au_check( i ); return; }
    if( b == '\n' || b == 0 ) return;                 /* ignore LF / NUL line ends */
    if( b == 8 || b == 127 ) {                        /* backspace */
        if( au_len[i] > 0 ) au_len[i]--;
        return;
    }
    if( au_len[i] < sizeof( au_buf[0] ) - 1 )
        au_buf[i][ au_len[i]++ ] = (char)b;
}

/* set up a newly connected slot: negotiate char mode, then either admit it
 * straight away (no password) or hold it at the password prompt. */
void telnet_begin( int i )
{
    telnet_reset( i );
    telnet_hello( i );
    /* ask the terminal to size itself to 80x25 (the fixed mirror geometry) so
     * the manual `printf '\e[8;25;80t'` step is usually unnecessary; terminals
     * that ignore it fall back to the documented manual resize. Not screen
     * content, so it is safe to send before authentication. */
    au_say( i, "\x1b[8;25;80t" );
    au_len[i] = 0;
    au_tries[i] = 0;
    if( g_password[0] ) {
        au_state[i] = AU_PW;
        au_say( i, "\r\nPassword: " );
    } else {
        au_state[i] = AU_OK;
        net_slot_ready( i, 1 );
        render_reset();
    }
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
        else if( opt == OPT_NAWS ) { /* we already sent DO NAWS in hello: accept, stay silent */ }
        else put3( i, IAC, DONT, opt );
    } else if( v == WONT ) {
        put3( i, IAC, DONT, opt );
    } else if( v == DONT ) {
        put3( i, IAC, WONT, opt );
    }
}

static void sb_push( int i, unsigned char b )
{
    if( sb_len[i] < sizeof( sb_buf[0] ) )
        sb_buf[i][ sb_len[i]++ ] = b;
}

/* a subnegotiation finished (IAC SE). If it was NAWS (opt 31, body = W_hi W_lo
 * H_hi H_lo, MSB first), record the size; a genuine LATER resize forces a full
 * repaint so the client's cleared/resized terminal is redrawn. The first report
 * doesn't repaint (the connect already painted), and the mirror stays 80x25. */
static void sb_done( int i )
{
    if( sb_len[i] >= 5 && sb_buf[i][0] == OPT_NAWS ) {
        unsigned w = ( (unsigned)sb_buf[i][1] << 8 ) | sb_buf[i][2];
        unsigned h = ( (unsigned)sb_buf[i][3] << 8 ) | sb_buf[i][4];
        if( w != naws_w[i] || h != naws_h[i] ) {
            int had = ( naws_w[i] != 0 || naws_h[i] != 0 );
            naws_w[i] = w; naws_h[i] = h;
            if( had && au_state[i] == AU_OK )
                render_reset();
        }
    }
}

void telnet_in( int i, unsigned char b )
{
    switch( iac[i] ) {
    case 0:
        if( b == IAC ) { iac[i] = 1; return; }
        feed_data( i, b );
        return;
    case 1:                                /* after IAC */
        if( b == IAC ) { feed_data( i, IAC ); iac[i] = 0; return; }  /* literal FF */
        if( b == SB )  { sb_len[i] = 0; iac[i] = 3; return; }
        if( b >= WILL && b <= DONT ) { verb[i] = b; iac[i] = 2; return; }
        iac[i] = 0; return;                /* IAC <other>: 2-byte, ignore */
    case 2:                                /* verb + option */
        respond( i, verb[i], b );
        iac[i] = 0; return;
    case 3:                                /* inside SB: collect the body */
        if( b == IAC ) { iac[i] = 4; return; }
        sb_push( i, b );
        return;
    case 4:                                /* SB + IAC */
        if( b == SE )  { sb_done( i ); iac[i] = 0; return; }  /* end of SB */
        if( b == IAC ) { sb_push( i, IAC ); iac[i] = 3; return; }  /* doubled FF */
        iac[i] = 3; return;                /* unexpected; keep collecting */
    }
}
