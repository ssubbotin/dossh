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

#ifdef DOSSH_SSH
/* SSH server variant (built medium-model -3; see build.sh). Everything SSH is
 * guarded by DOSSH_SSH so the default 8086 DOSSHD.EXE is byte-for-byte
 * unchanged. ssh.h/rng.h pull in the __far crypto primitives. */
#include "ssh.h"
#include "rng.h"
#endif

/* transport: 0 = serial (COM1), 1 = TCP over a packet driver (net.c) */
static int g_net;
static unsigned char net_ip[4] = { 10, 0, 2, 15 };
static unsigned      net_port  = 23;      /* the telnet port, so `telnet <host>` works */

#ifdef DOSSH_SSH
/* ---- SSH server state (resident, DGROUP) ---------------------------------
 * P1: a single SSH session bound to one net.c slot (multi-client SSH is P3).
 * The transport/framing is ssh.c where telnet.c sits on the net path; the same
 * TCP stack (net.c) carries it. */
static int          g_ssh_mode;             /* 1 = SSH transport                 */
static int          g_ssh_serial;           /* 1 = SSH over COM1, else over net   */
static int          g_ssh_ser_started;      /* serial: a session is in progress   */
static ssh_conn     g_ssh;                  /* the one SSH connection            */
static int          g_ssh_slot = -1;        /* net slot bound to it, -1 = idle   */
static unsigned char g_hostkey_sk[64];      /* resident ed25519 host key         */
static unsigned char g_hostkey_pk[32];
static char         g_ssh_pw[64];           /* configured password (empty = open) */
static int          g_ssh_have_pw;
#define SSH_MAX_AUTHKEYS 8                   /* a handful fits the DGROUP budget   */
static unsigned char g_authkeys[SSH_MAX_AUTHKEYS][32]; /* authorized ed25519 keys */
static unsigned      g_authkey_count;       /* loaded from AUTHKEYS at install    */
static int          g_ssh_cols = 80, g_ssh_rows = 25;   /* last client window     */
static unsigned     g_ssh_stir;             /* rolling ISR entropy sample        */
static int          g_ssh_stack_op;         /* dispatcher: 0 = tick, 1 = install  */

extern void ssh_run_on_stack( void );       /* sshtramp.asm: private-stack shim  */
void        ssh_stack_dispatch( void );     /* the shim calls this (extern)      */
static void ssh_worker( void );
static void ssh_net_worker( void );
static void ssh_serial_worker( void );
static void ssh_install_setup( void );
#endif

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
static volatile int g_reboot;             /* set by the console warm-reboot sentinel */

/* ansikey.c calls this when it sees the reboot sentinel; the actual reboot runs
 * at the tick-ISR tail (never nested inside net servicing). */
void request_reboot( void ) { g_reboot = 1; }

/* Programmatic warm boot: stop the NIC, set the BIOS warm-boot flag (skip the
 * POST memory test), and pulse the CPU reset line via the 8042 keyboard
 * controller. Injected Ctrl+Alt+Del does NOT work (INT 9h reads the real
 * shift-state, not the type-ahead ring), and a jump to FFFF:0000 does not reset
 * under SeaBIOS - the 8042 reset is reliable on real hardware and QEMU. */
static void do_reboot( void )
{
    volatile unsigned i;
    g_reboot = 0;                                  /* one attempt */
    if( g_net )                                    /* stop the NIC first */
        net_release( net_pkt_int(), net_pkt_handle() );
    _disable();
    *(unsigned short __far *)MK_FP( 0x40, 0x72 ) = 0x1234;   /* 1234h = warm */
    outp( 0x64, 0xFE );                            /* 8042: pulse CPU reset */
    for( i = 0; i < 60000U; i++ )                  /* wait for it to fire */
        ;
    _enable();                                     /* did not reset? resume */
}

static void net_tick( void )
{
    int i, b;

    net_poll();                               /* rx + tcp + retransmit */

    /* each newly ESTABLISHED client: negotiate char mode and run the auth gate.
       With no password telnet_begin admits it and forces a full repaint (one
       repaint per join is the cost of the shared stream); with a password it
       prompts and holds the slot out of the broadcast until it authenticates. */
    while( (i = net_take_new_slot()) >= 0 )
        telnet_begin( i );

    /* merge keystrokes from every client into the one BIOS ring */
    for( i = 0; i < net_slots(); i++ )
        while( (b = net_rx_getc( i )) >= 0 )
            telnet_in( i, (unsigned char)b );

    if( net_connected() ) {
        tx_pump();                            /* broadcast screen bytes */
        net_tx_flush();                       /* push them as segments  */
    }
}

#ifdef DOSSH_SSH
/* ---- SSH tick worker -------------------------------------------------------
 * Runs on a private DGROUP stack (see sshtramp.asm) so the medium-model crypto's
 * near-data stack buffers resolve correctly at interrupt time (SS == DS). It is
 * the SSH analogue of net_tick: net_poll drives TCP, ssh.c is the per-connection
 * framing, and the render/ansikey layers above it are untouched (they see
 * decrypted bytes, just as telnet sees post-IAC bytes). */

/* drain ssh_output() to the bound slot's TCP send ring, bounded by ring room so
 * no encrypted byte is ever dropped - leftover stays queued inside ssh's ob. */
static void ssh_pump_output( int slot )
{
    unsigned char buf[128];
    unsigned room, n, k;

    for( ;; ) {
        room = (unsigned)net_tx_room_slot( slot );
        if( room == 0 ) break;
        if( room > sizeof( buf ) ) room = sizeof( buf );
        n = ssh_output( &g_ssh, buf, room );
        if( n == 0 ) break;
        for( k = 0; k < n; k++ )
            net_tx_putc_slot( slot, buf[k] );  /* fits: bounded by room above */
    }
}

/* pull render bytes and stage them as SSH channel data (mirrors tx_pump); the
 * channel's return-0-when-full paces the shared stream exactly like the net path */
static void ssh_tx_pump( void )
{
    unsigned budget = TX_BUDGET;

    while( budget-- ) {
        int b = render_next_byte( 0 );         /* network cadence (serial=0) */
        if( b < 0 )
            break;
        if( !ssh_channel_putc( &g_ssh, b ) ) { /* staging buffer full */
            render_pushback( b );              /* ... resume next tick */
            break;
        }
    }
}

/* dispatch the tick worker to the active SSH transport (both run on the private
 * stack, so the crypto's stack buffers are near-correct) */
static void ssh_worker( void )
{
    if( g_ssh_serial )
        ssh_serial_worker();
    else
        ssh_net_worker();
}

static void ssh_net_worker( void )
{
    int i, b;

    net_poll();                                /* rx + tcp + retransmit */

    /* new TCP connections: bind the first to the single P1 SSH session and hand
       it our version string + KEXINIT; reject the rest (multi-client SSH is P3). */
    while( ( i = net_take_new_slot() ) >= 0 ) {
        if( g_ssh_slot < 0 || i == g_ssh_slot ) {
            g_ssh_slot = i;
            ssh_reset( &g_ssh, g_hostkey_sk, g_hostkey_pk );
            if( g_ssh_have_pw )
                ssh_set_password( &g_ssh, g_ssh_pw );
            if( g_authkey_count )
                ssh_set_authorized_keys( &g_ssh,
                                         (const unsigned char *)g_authkeys,
                                         g_authkey_count );
            g_ssh_cols = 80; g_ssh_rows = 25;
            render_reset();                    /* first channel data repaints */
            ssh_pump_output( g_ssh_slot );     /* SSH-2.0-... + KEXINIT        */
        } else {
            net_slot_drop( i );
        }
    }

    if( g_ssh_slot < 0 )
        return;
    if( !net_slot_connected( g_ssh_slot ) ) {  /* peer went away: free the session */
        g_ssh_slot = -1;
        return;
    }

    /* inbound SSH wire bytes -> the state machine (which queues any replies) */
    {
        unsigned char rb[512];
        unsigned rn = 0;
        while( rn < sizeof( rb ) && ( b = net_rx_getc( g_ssh_slot ) ) >= 0 ) {
            rng_stir( (unsigned)b ^ g_ssh_stir++ );   /* fold arrival jitter */
            rb[rn++] = (unsigned char)b;
        }
        if( rn )
            ssh_input( &g_ssh, rb, rn );
    }
    ssh_pump_output( g_ssh_slot );             /* handshake / protocol replies */

    if( ssh_channel_ready( &g_ssh ) ) {        /* shell granted: byte pipe is up */
        int cols, rows;
        ssh_winsize( &g_ssh, &cols, &rows );   /* SSH's NAWS equivalent */
        if( cols != g_ssh_cols || rows != g_ssh_rows ) {
            g_ssh_cols = cols; g_ssh_rows = rows;
            render_reset();                    /* client resized: full repaint */
        }
        while( ( b = ssh_channel_getc( &g_ssh ) ) >= 0 )
            ansi_key_byte( (unsigned char)b );  /* keystrokes -> BIOS ring (+ reboot sentinel) */
        ssh_tx_pump();                          /* screen -> channel staging */
        ssh_channel_flush( &g_ssh );            /* frame + encrypt as CHANNEL_DATA */
        ssh_pump_output( g_ssh_slot );
    }

    /* teardown: peer closed the channel / sent DISCONNECT, or a fatal error */
    if( ssh_channel_closed( &g_ssh ) || ssh_failed( &g_ssh )
        || g_ssh.state == SSH_ST_CLOSED ) {
        ssh_pump_output( g_ssh_slot );          /* push any final bytes first */
        net_slot_drop( g_ssh_slot );
        g_ssh_slot = -1;
    }

    rng_stir( g_ssh_stir++ );                   /* continuous stir in the ISR */
}

/* ---- SSH over COM1 --------------------------------------------------------
 * The same ssh.c transport, but the byte stream is the 16550 UART instead of
 * net.c. Point-to-point, so there is no connection event: the server can't
 * speak first. We wait for the client's first bytes (its "SSH-" version line),
 * then ssh_reset (which queues our version + KEXINIT) and feed them in. Under
 * QEMU a `-serial tcp:...,server` bridge makes this reachable by a stock `ssh`
 * pointed at the bridged port - the SSH crypto still terminates on the DOS box. */

/* drain ssh_output() onto COM1, bounded per tick to keep the ISR budget */
static void ssh_serial_pump_output( void )
{
    unsigned char buf[128];
    unsigned n, k, budget = 1024;

    while( budget ) {
        unsigned take = budget < sizeof( buf ) ? budget : sizeof( buf );
        n = ssh_output( &g_ssh, buf, take );
        if( n == 0 )
            break;
        for( k = 0; k < n; k++ ) {
            unsigned guard = 0;
            while( ( inp( U_LSR ) & 0x20 ) == 0 )   /* wait for THR empty */
                if( ++guard > 60000U ) break;       /* no peer: don't hang */
            outp( U_THR, buf[k] );
        }
        budget -= n;
    }
}

static void ssh_serial_worker( void )
{
    unsigned char rb[256];
    unsigned rn = 0;
    int b;

    while( rn < sizeof( rb ) && ( inp( U_LSR ) & 0x01 ) ) {   /* RX ready */
        b = inp( U_RBR );
        rng_stir( (unsigned)b ^ g_ssh_stir++ );
        rb[rn++] = (unsigned char)b;
    }

    if( rn ) {
        /* start (or restart, after a prior session ended/errored) on first bytes */
        if( !g_ssh_ser_started || g_ssh.state == SSH_ST_ERROR
            || g_ssh.state == SSH_ST_CLOSED ) {
            ssh_reset( &g_ssh, g_hostkey_sk, g_hostkey_pk );
            if( g_ssh_have_pw )
                ssh_set_password( &g_ssh, g_ssh_pw );
            if( g_authkey_count )
                ssh_set_authorized_keys( &g_ssh,
                                         (const unsigned char *)g_authkeys,
                                         g_authkey_count );
            g_ssh_cols = 80; g_ssh_rows = 25;
            g_ssh_ser_started = 1;
            render_reset();
        }
        ssh_input( &g_ssh, rb, rn );
    }

    if( !g_ssh_ser_started )
        return;

    ssh_serial_pump_output();                  /* handshake / protocol replies */

    if( ssh_channel_ready( &g_ssh ) ) {
        int cols, rows;
        ssh_winsize( &g_ssh, &cols, &rows );
        if( cols != g_ssh_cols || rows != g_ssh_rows ) {
            g_ssh_cols = cols; g_ssh_rows = rows;
            render_reset();
        }
        while( ( b = ssh_channel_getc( &g_ssh ) ) >= 0 )
            ansi_key_byte( (unsigned char)b );
        ssh_tx_pump();
        ssh_channel_flush( &g_ssh );
        ssh_serial_pump_output();
    }

    rng_stir( g_ssh_stir++ );
}

/* Called by the private-stack shim (sshtramp.asm). Runs either the per-tick SSH
 * worker or, once at install, the entropy gather + host-key generation - both on
 * the deep private stack (the crypto needs it). */
void ssh_stack_dispatch( void )
{
    if( g_ssh_stack_op )
        ssh_install_setup();
    else
        ssh_worker();
}
#endif /* DOSSH_SSH */

static void __interrupt __far tick_isr( void )
{
    if( !in_tick ) {
        in_tick = 1;
        ansi_key_tick();                      /* flush a pending lone ESC */
#ifdef DOSSH_SSH
        if( g_ssh_mode )
            ssh_run_on_stack();               /* SSH work, on a private DGROUP stack */
        else
#endif
        if( g_net ) {
            net_tick();
        } else {
            pump_rx();
            tx_pump();
        }
        in_tick = 0;
    }
    if( g_reboot )                            /* console asked for a warm reboot */
        do_reboot();                          /* ... at the tail; never returns */
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

#ifdef DOSSH_SSH
/* Load the persistent ed25519 host key from DOSSHD.KEY (a 32-byte seed in the
 * current directory) or generate + persist one on first install. Read-only
 * media: the freshly generated key is used for this boot only (warned). This is
 * the foreground path, so ordinary DOS file I/O is fine. */
static void ssh_load_hostkey( void )
{
    unsigned char seed[32];
    FILE *f;
    int have = 0;

    f = fopen( "DOSSHD.KEY", "rb" );
    if( f ) {
        if( fread( seed, 1, 32, f ) == 32 )
            have = 1;
        fclose( f );
    }
    if( !have ) {
        rng_bytes( seed, 32 );                /* CSPRNG (rng_init already ran) */
        f = fopen( "DOSSHD.KEY", "wb" );
        if( f ) {
            fwrite( seed, 1, 32, f );
            fclose( f );
            printf( "DOSSHD: generated a new ed25519 host key (DOSSHD.KEY).\n" );
        } else {
            printf( "DOSSHD: WARNING - could not write DOSSHD.KEY;"
                    " host key is ephemeral this boot.\n" );
        }
    }
    dossh_ed25519_key_pair( g_hostkey_sk, g_hostkey_pk, seed );  /* wipes seed */
}

/* Load authorized ed25519 public keys from AUTHKEYS (an OpenSSH authorized_keys
 * file next to the EXE) at install. Each accepted line contributes one raw
 * 32-byte key to the resident set; publickey userauth (RFC 4252 sec 7) then lets
 * a matching client in with no secret on the wire. Absent file => publickey
 * simply unavailable and password auth still works. Foreground path (like the
 * host key), so ordinary DOS file I/O is fine. ssh-ed25519 only: the crypto
 * library has no RSA. */
static void ssh_load_authkeys( void )
{
    char line[300];                           /* one authorized_keys line       */
    FILE *f;

    g_authkey_count = 0;
    f = fopen( "AUTHKEYS", "r" );
    if( !f )
        return;                               /* no file: publickey unavailable */
    while( g_authkey_count < SSH_MAX_AUTHKEYS && fgets( line, sizeof( line ), f ) ) {
        if( ssh_parse_authkey_line( line, g_authkeys[g_authkey_count] ) )
            g_authkey_count++;
    }
    fclose( f );
    if( g_authkey_count )
        printf( "DOSSHD: loaded %u authorized ed25519 key(s) from AUTHKEYS.\n",
                g_authkey_count );
}

/* one-time install setup, run on the deep private stack via the shim */
static void ssh_install_setup( void )
{
    rng_init();                               /* gather entropy + seed the DRBG */
    ssh_load_hostkey();                       /* persistent ed25519 host key    */
    ssh_load_authkeys();                      /* authorized publickeys (AUTHKEYS) */
}
#endif

static int install( void )
{
    unsigned short psp = get_psp();
    unsigned short env, paras;

    ansi_key_init();                          /* build the keystroke tables */
    render_reset();                           /* first tick paints the screen */

#ifdef DOSSH_SSH
    if( g_ssh_mode ) {
        g_ssh_stack_op = 1;                   /* run rng_init + keygen on the    */
        ssh_run_on_stack();                   /* deep private stack (SS==DS here) */
        g_ssh_stack_op = 0;                   /* ... ticks use the worker path   */
    }
#endif

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
#ifdef DOSSH_SSH
    {
    const char *authdesc =
        g_authkey_count ? ( g_ssh_have_pw ? "publickey+password" : "publickey" )
                        : ( g_ssh_have_pw ? "password"           : "open (no /P)" );
    if( g_ssh_mode && g_ssh_serial )
        printf( "DOSSHD SSH (EXPERIMENTAL) - resident SSH console on COM1 (115200 8N1),\n"
                "  ed25519 host key, %s auth, %u KB kept.  `ssh` the bridged port; DOSSHD /U removes it.\n",
                authdesc,
                (unsigned)(((unsigned long)paras * 16 + 1023) / 1024) );
    else if( g_ssh_mode )
        printf( "DOSSHD SSH (EXPERIMENTAL) - resident SSH console on TCP %u.%u.%u.%u:%u,\n"
                "  ed25519 host key, %s auth, %u KB kept.  `ssh -p %u user@host`; DOSSHD /U removes it.\n",
                net_ip[0], net_ip[1], net_ip[2], net_ip[3], net_port,
                authdesc,
                (unsigned)(((unsigned long)paras * 16 + 1023) / 1024), net_port );
    else
    {
#endif
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
#ifdef DOSSH_SSH
    }                                         /* non-SSH transport branch */
    }                                         /* authdesc scope           */
#endif
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
#ifdef DOSSH_SSH
        if( opt_is( argv[1], "SSH" ) ) {      /* SSH server: same TCP path, ssh.c framing */
            int ai, pos = 0;                  /* positional args: 0 = ip, 1 = port */
            g_ssh_mode = 1;
            g_net      = 1;                   /* SSH rides the net.c TCP stack */
            net_port   = 22;                  /* default to the SSH port */
            for( ai = 2; ai < argc; ai++ ) {
                char *a = argv[ai];
                if( ( a[0] == '/' || a[0] == '-' )
                    && ( a[1] == 'P' || a[1] == 'p' ) && a[2] == ':' ) {
                    unsigned k = 0;           /* /P:<pw> -> ssh_set_password later */
                    const char *pw = a + 3;
                    while( pw[k] && k < sizeof( g_ssh_pw ) - 1 ) { g_ssh_pw[k] = pw[k]; k++; }
                    g_ssh_pw[k] = 0;
                    g_ssh_have_pw = ( k > 0 );
                } else if( opt_is( a, "COM" ) || opt_is( a, "COM1" )
                           || stricmp( a, "COM1" ) == 0 ) {
                    g_ssh_serial = 1;         /* SSH over the COM1 serial line */
                    g_net        = 0;
                } else if( pos == 0 ) {
                    if( !parse_ip( a, net_ip ) ) {
                        printf( "DOSSHD: bad IP '%s'\n", a );
                        return 1;
                    }
                    pos = 1;
                } else if( pos == 1 ) {
                    net_port = (unsigned)atoi( a );
                    pos = 2;
                }
            }
        } else
#endif
        if( opt_is( argv[1], "NET" ) ) {
            int ai, pos = 0;                  /* positional args: 0 = ip, 1 = port */
            g_net = 1;
            for( ai = 2; ai < argc; ai++ ) {
                char *a = argv[ai];
                if( ( a[0] == '/' || a[0] == '-' )
                    && ( a[1] == 'P' || a[1] == 'p' ) && a[2] == ':' ) {
                    telnet_set_password( a + 3 ); /* /P:<pw> anywhere on the line */
                } else if( pos == 0 ) {
                    if( !parse_ip( a, net_ip ) ) {
                        printf( "DOSSHD: bad IP '%s'\n", a );
                        return 1;
                    }
                    pos = 1;
                } else if( pos == 1 ) {
                    net_port = (unsigned)atoi( a );
                    pos = 2;
                }
            }
        } else {
            printf( "usage: DOSSHD                       install over serial (COM1)\n"
                    "       DOSSHD /NET [ip] [port] [/P:pw]  install over TCP (port 23;\n"
                    "                                        /P: gates with a password)\n"
                    "       DOSSHD /S                    status\n"
                    "       DOSSHD /U                    uninstall\n" );
#ifdef DOSSH_SSH
            printf( "       DOSSHD /SSH [ip] [port] [/P:pw]  install as an SSH server over TCP\n"
                    "       DOSSHD /SSH /COM [/P:pw]         install as an SSH server over COM1\n"
                    "                                        (EXPERIMENTAL; port 22; /P: sets the password)\n" );
#endif
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
