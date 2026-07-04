/*
 * DOSSHD - the DOS-side server for DOSSH (https://github.com/ssubbotin/dossh)
 *
 * M3/M4: resident (TSR) remote console, over serial or the network.
 *     DOSSHD hooks the timer tick (INT 1Ch) and goes resident; the tick
 *     handler mirrors the VGA text screen out the chosen transport in
 *     budgeted chunks and pumps received KEY frames into the BIOS keyboard
 *     buffer. Whatever runs in the foreground afterwards - COMMAND.COM, a
 *     BIOS flasher, an installer - is mirrored and remotely driven, with no
 *     cooperation from the program.
 *
 *         DOSSHD               install over COM1 (serial)
 *         DOSSHD /NET [ip] [port]  install over TCP via a packet driver
 *         DOSSHD /S            status
 *         DOSSHD /U            uninstall (unhook + free the resident memory)
 *
 *     Install forms are AUTOEXEC.BAT-friendly: they go resident and return.
 *     The tick path is DOS-call-free (port I/O, far memory, and the packet
 *     driver only), so it is safe regardless of what the foreground program
 *     is doing in DOS - the classic InDOS/reentrancy trap never applies.
 *     Presence detection and uninstall use an INT 2Fh multiplex handler
 *     (AH=D5h) that hands back a magic-tagged state block.
 *
 * The M4 transport is TCP carried over a DOS packet driver (net.c); the wire
 * protocol above the byte stream is identical to the serial path, so the same
 * client drives either. Under QEMU, `-serial tcp:...,server` bridges COM1 for
 * the serial path, and user-net `hostfwd` reaches the packet-driver path.
 *
 * Build: Open Watcom, 16-bit real mode  ->  see build.sh
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <conio.h>
#include <dos.h>
#include <i86.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net.h"
#include "render.h"
#include "ansikey.h"
#include "telnet.h"

/* transport: 0 = serial (COM1), 1 = TCP over a packet driver (net.c) */
static int g_net;
static unsigned char net_ip[4] = { 10, 0, 2, 15 };
static unsigned      net_port  = 5555;

/* ---- COM1 16550 UART, polled ---------------------------------------- */
#define COM1      0x3F8
#define U_RBR     (COM1 + 0)   /* RX buffer   (DLAB=0, read)  */
#define U_THR     (COM1 + 0)   /* TX holding  (DLAB=0, write) */
#define U_DLL     (COM1 + 0)   /* divisor low (DLAB=1) */
#define U_DLM     (COM1 + 1)   /* divisor high(DLAB=1) */
#define U_IER     (COM1 + 1)
#define U_FCR     (COM1 + 2)
#define U_LCR     (COM1 + 3)
#define U_MCR     (COM1 + 4)
#define U_LSR     (COM1 + 5)

/* payload bytes pushed per timer tick; at 18.2 ticks/s this paces the
   mirror to ~2 fps for a full 80x25 frame and bounds time spent in the
   ISR on real 115200 hardware */
#define TX_BUDGET 512

/* INT 2Fh multiplex id for presence check / uninstall handshake */
#define MPX_ID    0xD5
#define STATE_MAGIC "DOSSH1"

static void uart_init( void )
{
    outp( U_IER, 0x00 );       /* polled, no interrupts        */
    outp( U_LCR, 0x80 );       /* DLAB = 1                     */
    outp( U_DLL, 0x01 );       /* divisor 1 -> 115200 baud     */
    outp( U_DLM, 0x00 );
    outp( U_LCR, 0x03 );       /* 8 data bits, no parity, 1 stop, DLAB=0 */
    outp( U_FCR, 0xC7 );       /* enable + clear FIFOs          */
    outp( U_MCR, 0x03 );       /* DTR, RTS                     */
}

/* Screen scrape + the ANSI screen renderer live in render.c. */

/* ---- resident state, discoverable through INT 2Fh -------------------- */

struct resident_state {
    char magic[6];                            /* STATE_MAGIC              */
    unsigned short psp;                       /* resident PSP segment     */
    unsigned char  mode;                      /* 0 = serial, 1 = net      */
    unsigned char  pkt_int;                   /* packet-driver INT (net)  */
    unsigned       pkt_handle;                /* access_type handle (net) */
    void (__interrupt __far *old_1c)( void );
    void (__interrupt __far *old_2f)( void );
};

static struct resident_state state;

/* ---- keyboard injection: the BIOS type-ahead ring at 0040:001E ------- */

/* non-static: ansikey.c injects mapped keystrokes through this */
void inject_key( unsigned char scan, unsigned char ascii )
{
    unsigned short __far *head = (unsigned short __far *)MK_FP( 0x40, 0x1A );
    unsigned short __far *tail = (unsigned short __far *)MK_FP( 0x40, 0x1C );
    unsigned short bstart = *(unsigned short __far *)MK_FP( 0x40, 0x80 );
    unsigned short bend   = *(unsigned short __far *)MK_FP( 0x40, 0x82 );
    unsigned short next;

    if( bstart < 0x1E || bend <= bstart ) {   /* pre-AT BIOS: fixed ring */
        bstart = 0x1E;
        bend   = 0x3E;
    }
    _disable();
    next = *tail + 2;
    if( next >= bend )
        next = bstart;
    if( next != *head ) {                     /* drop the key if ring full */
        *(unsigned short __far *)MK_FP( 0x40, *tail ) =
            ((unsigned short)scan << 8) | ascii;
        *tail = next;
    }
    _enable();
}

/* ---- input: raw terminal bytes -> keystrokes (ansikey.c) ------------- */

static void pump_rx( void )
{
    while( inp( U_LSR ) & 0x01 )
        ansi_key_byte( (unsigned char)inp( U_RBR ) );
}

/* ---- screen TX: pull ANSI bytes from render.c, pace onto the transport --- */

static void tx_pump( void )
{
    unsigned budget = TX_BUDGET;

    while( budget-- ) {
        int b = render_next_byte( !g_net );
        if( b < 0 )
            break;                            /* nothing more to send now */
        if( g_net ) {
            if( !net_tx_putc( b ) ) {         /* TCP send buffer full */
                render_pushback( b );         /* ... resume next tick */
                break;
            }
        } else {
            while( (inp( U_LSR ) & 0x20) == 0 )   /* wait for TX holding empty */
                pump_rx();                    /* ... without dropping keys */
            outp( U_THR, (unsigned char)b );
        }
    }
}

/* ---- resident interrupt handlers -------------------------------------- */

static volatile int in_tick;

static void net_tick( void )
{
    static int was_conn;
    int b, conn;

    net_poll();                               /* rx + tcp + retransmit */

    conn = net_connected();
    if( conn && !was_conn ) {                 /* new client */
        telnet_reset();
        telnet_hello();                       /* negotiate char mode */
        render_reset();                       /* then full repaint   */
    }
    was_conn = conn;

    while( (b = net_rx_getc()) >= 0 )         /* strip IAC, map keystrokes */
        telnet_in( (unsigned char)b );

    if( conn ) {
        tx_pump();                            /* queue screen bytes  */
        net_tx_flush();                       /* push them as segments */
    }
}

static void __interrupt __far tick_isr( void )
{
    if( !in_tick ) {
        in_tick = 1;
        ansi_key_tick();                      /* flush a pending lone ESC */
        if( g_net ) {
            net_tick();
        } else {
            pump_rx();
            tx_pump();
        }
        in_tick = 0;
    }
    _chain_intr( state.old_1c );
}

static void __interrupt __far mpx_isr( union INTPACK r )
{
    if( r.h.ah == MPX_ID && r.h.al == 0x00 ) {  /* presence check */
        r.h.al = 0xFF;
        r.w.cx = FP_SEG( (void __far *)&state );
        r.w.dx = FP_OFF( (void __far *)&state );
        return;
    }
    _chain_intr( state.old_2f );
}

/* ---- transient part: install / status / uninstall --------------------- */

static unsigned short get_psp( void )
{
    union REGS r;
    r.h.ah = 0x62;                            /* DOS 3+: get PSP segment */
    int86( 0x21, &r, &r );
    return r.w.bx;
}

static unsigned short block_paras( unsigned short psp )
{
    /* size of a program's memory block, from its MCB (the paragraph
       right below the PSP) */
    return *(unsigned short __far *)MK_FP( psp - 1, 3 );
}

/* NULL: not installed. Otherwise the resident state block - unless the
   multiplex id belongs to someone else, reported via *conflict. */
static struct resident_state __far *find_resident( int *conflict )
{
    union REGS r;

    *conflict = 0;
    r.w.ax = (MPX_ID << 8) | 0x00;
    r.w.cx = 0;
    r.w.dx = 0;
    int86( 0x2F, &r, &r );
    if( r.h.al != 0xFF )
        return NULL;
    if( r.w.cx | r.w.dx ) {
        struct resident_state __far *st =
            (struct resident_state __far *)MK_FP( r.w.cx, r.w.dx );
        if( _fmemcmp( st->magic, STATE_MAGIC, 6 ) == 0 )
            return st;
    }
    *conflict = 1;
    return NULL;
}

static int install( void )
{
    unsigned short psp = get_psp();
    unsigned short env, paras;

    ansi_key_init();                          /* build the keystroke tables */
    render_reset();                           /* first tick paints the screen */

    if( g_net ) {
        if( !net_open( net_ip[0], net_ip[1], net_ip[2], net_ip[3],
                       net_port ) ) {
            printf( "DOSSHD: no packet driver found (is one loaded?).\n" );
            return 1;
        }
    } else {
        uart_init();
    }

    memcpy( state.magic, STATE_MAGIC, 6 );
    state.psp        = psp;
    state.mode       = (unsigned char)g_net;
    state.pkt_int    = g_net ? net_pkt_int() : 0;
    state.pkt_handle = g_net ? net_pkt_handle() : 0;
    state.old_1c = _dos_getvect( 0x1C );
    state.old_2f = _dos_getvect( 0x2F );
    _dos_setvect( 0x2F, mpx_isr );
    _dos_setvect( 0x1C, tick_isr );

    /* the environment block is not needed once resident */
    env = *(unsigned short __far *)MK_FP( psp, 0x2C );
    if( env ) {
        _dos_freemem( env );
        *(unsigned short __far *)MK_FP( psp, 0x2C ) = 0;
    }

    paras = block_paras( psp );
    if( g_net )
        printf( "DOSSHD M4 - resident console over TCP %u.%u.%u.%u:%u via %02X:%02X:%02X:%02X:%02X:%02X,\n"
                "  %u KB kept.  Connect a client; DOSSHD /U removes it.\n",
                net_ip[0], net_ip[1], net_ip[2], net_ip[3], net_port,
                g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5],
                (unsigned)(((unsigned long)paras * 16 + 1023) / 1024) );
    else
        printf( "DOSSHD M3 - resident console on COM1 (115200 8N1), %u KB kept.\n"
                "Screen is mirrored and remote keys injected until DOSSHD /U.\n",
                (unsigned)(((unsigned long)paras * 16 + 1023) / 1024) );
    _dos_keep( 0, paras );                    /* stay resident; no return */
    return 0;                                 /* not reached */
}

static int uninstall( void )
{
    int conflict;
    struct resident_state __far *st = find_resident( &conflict );
    void (__interrupt __far *old1c)( void );
    void (__interrupt __far *old2f)( void );
    unsigned short rpsp, rend;
    unsigned short seg1c, seg2f;

    if( st == NULL ) {
        printf( conflict ? "DOSSHD: multiplex id %02Xh is taken by another TSR.\n"
                         : "DOSSHD: not installed.\n", MPX_ID );
        return 1;
    }
    /* only unhook if both vectors still point into the resident block;
       otherwise another TSR hooked after us and unhooking would crash it */
    rpsp  = st->psp;
    rend  = rpsp + block_paras( rpsp );
    seg1c = FP_SEG( _dos_getvect( 0x1C ) );
    seg2f = FP_SEG( _dos_getvect( 0x2F ) );
    if( seg1c < rpsp || seg1c >= rend || seg2f < rpsp || seg2f >= rend ) {
        printf( "DOSSHD: another TSR hooked INT 1Ch/2Fh after DOSSHD;\n"
                "        remove it first, then retry DOSSHD /U.\n" );
        return 1;
    }
    old1c = st->old_1c;                       /* copy out before freeing */
    old2f = st->old_2f;
    _disable();
    _dos_setvect( 0x1C, old1c );
    _dos_setvect( 0x2F, old2f );
    _enable();
    /* net mode: unregister our receiver from the packet driver before the
       memory holding it is freed, or the next frame calls into freed code.
       Use the resident copy's driver int/handle (this transient DOSSHD has
       its own zeroed net.c globals). */
    if( st->mode )
        net_release( st->pkt_int, st->pkt_handle );
    _dos_freemem( rpsp );
    printf( "DOSSHD: uninstalled.\n" );
    return 0;
}

static int status( void )
{
    int conflict;
    struct resident_state __far *st = find_resident( &conflict );

    if( st ) {
        printf( "DOSSHD: installed (%s), resident at %04X:0000.\n",
                st->mode ? "network" : "serial", st->psp );
        return 0;
    }
    printf( conflict ? "DOSSHD: multiplex id %02Xh is taken by another TSR.\n"
                     : "DOSSHD: not installed.\n", MPX_ID );
    return 1;
}

/* parse "a.b.c.d" into out[4]; returns 1 on success */
static int parse_ip( const char *s, unsigned char *out )
{
    int i;
    for( i = 0; i < 4; i++ ) {
        long v = 0;
        if( *s < '0' || *s > '9' )
            return 0;
        while( *s >= '0' && *s <= '9' )
            v = v * 10 + ( *s++ - '0' );
        if( v > 255 )
            return 0;
        out[i] = (unsigned char)v;
        if( i < 3 ) {
            if( *s != '.' )
                return 0;
            s++;
        }
    }
    return *s == '\0';
}

static int opt_is( const char *a, const char *name )
{
    if( a[0] != '/' && a[0] != '-' )
        return 0;
    return stricmp( a + 1, name ) == 0;
}

int main( int argc, char *argv[] )
{
    int conflict;

    if( argc > 1 ) {
        if( opt_is( argv[1], "U" ) ) return uninstall();
        if( opt_is( argv[1], "S" ) ) return status();
        if( opt_is( argv[1], "NET" ) ) {
            g_net = 1;
            if( argc > 2 && !parse_ip( argv[2], net_ip ) ) {
                printf( "DOSSHD: bad IP '%s'\n", argv[2] );
                return 1;
            }
            if( argc > 3 )
                net_port = (unsigned)atoi( argv[3] );
        } else {
            printf( "usage: DOSSHD                    install over serial (COM1)\n"
                    "       DOSSHD /NET [ip] [port]   install over TCP (packet driver)\n"
                    "       DOSSHD /S                 status\n"
                    "       DOSSHD /U                 uninstall\n" );
            return 1;
        }
    }
    if( find_resident( &conflict ) ) {
        printf( "DOSSHD: already installed.\n" );
        return 1;
    }
    if( conflict ) {
        printf( "DOSSHD: multiplex id %02Xh is taken by another TSR.\n", MPX_ID );
        return 1;
    }
    return install();
}
