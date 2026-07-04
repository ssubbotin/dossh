/*
 * DOSSHD - the DOS-side server for DOSSH (https://github.com/ssubbotin/dossh)
 *
 * M3: resident (TSR) remote console over COM1.
 *     DOSSHD hooks the timer tick (INT 1Ch) and goes resident; the tick
 *     handler mirrors the VGA text screen out the serial port in budgeted
 *     chunks and pumps received KEY frames into the BIOS keyboard buffer.
 *     Whatever runs in the foreground afterwards - COMMAND.COM, a BIOS
 *     flasher, an installer - is mirrored and remotely driven, with no
 *     cooperation from the program.
 *
 *         DOSSHD          install (AUTOEXEC.BAT-friendly: it returns)
 *         DOSSHD /S       status
 *         DOSSHD /U       uninstall (unhook + free the resident memory)
 *
 *     The tick path is DOS-call-free (port I/O and far memory only), so it
 *     is safe regardless of what the foreground program is doing in DOS -
 *     the classic InDOS/reentrancy trap never applies. Presence detection
 *     and uninstall use an INT 2Fh multiplex handler (AH=D5h) that hands
 *     back a magic-tagged state block.
 *
 * Transport is still the serial port (under QEMU, `-serial tcp:...,server`
 * bridges COM1 to a host TCP socket). A packet-driver transport is the next
 * milestone.
 *
 * Build: Open Watcom, 16-bit real mode  ->  see build.sh
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <conio.h>
#include <dos.h>
#include <i86.h>
#include <stdio.h>
#include <string.h>

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

/* ---- text-screen geometry from the BIOS Data Area (segment 0x40) ---- */
static unsigned char __far *bda = (unsigned char __far *)MK_FP( 0x40, 0 );

static unsigned scr_cols( void ) { return bda[0x4A]; }               /* # columns */
static unsigned scr_rows( void ) { return bda[0x84] + 1; }           /* rows-1 (EGA+); 0 -> 25 */
static unsigned char scr_mode( void ) { return bda[0x49]; }          /* current video mode */

static unsigned char __far *scr_base( void )
{
    /* mode 7 is monochrome text at B000:0; colour text lives at B800:0 */
    return (scr_mode() == 7) ? (unsigned char __far *)MK_FP( 0xB000, 0 )
                             : (unsigned char __far *)MK_FP( 0xB800, 0 );
}

static void cursor_pos( unsigned char *row, unsigned char *col )
{
    unsigned pos = *(unsigned __far *)&bda[0x50];   /* page 0: low=col, high=row */
    *col = (unsigned char)(pos & 0xFF);
    *row = (unsigned char)((pos >> 8) & 0xFF);
}

static void put16( unsigned char *b, unsigned v )
{
    b[0] = (unsigned char)(v & 0xFF);
    b[1] = (unsigned char)((v >> 8) & 0xFF);
}

/* ---- resident state, discoverable through INT 2Fh -------------------- */

struct resident_state {
    char magic[6];                            /* STATE_MAGIC              */
    unsigned short psp;                       /* resident PSP segment     */
    void (__interrupt __far *old_1c)( void );
    void (__interrupt __far *old_2f)( void );
};

static struct resident_state state;

/* ---- keyboard injection: the BIOS type-ahead ring at 0040:001E ------- */

static void inject_key( unsigned char scan, unsigned char ascii )
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

/* ---- client -> server KEY frames: "DSSH", 2, scan, ascii, modifiers -- */

static unsigned char rxbuf[8];
static unsigned rxlen;

static void rx_byte( unsigned char b )
{
    static const unsigned char prefix[5] = { 'D', 'S', 'S', 'H', 2 };
    unsigned i;

    rxbuf[rxlen++] = b;
    for( ;; ) {
        for( i = 0; i < rxlen && i < 5; i++ ) {
            if( rxbuf[i] != prefix[i] )
                break;
        }
        if( i == rxlen || i == 5 ) {          /* prefix still plausible */
            if( rxlen == 8 ) {
                inject_key( rxbuf[5], rxbuf[6] );
                rxlen = 0;
            }
            return;
        }
        for( i = 1; i < rxlen; i++ )          /* resync: slide one byte */
            rxbuf[i - 1] = rxbuf[i];
        rxlen--;
        if( rxlen == 0 )
            return;
    }
}

static void pump_rx( void )
{
    while( inp( U_LSR ) & 0x01 )
        rx_byte( (unsigned char)inp( U_RBR ) );
}

/* ---- screen TX state machine (one SCREEN frame across many ticks) ---- */

static unsigned char hdr[14];
static unsigned tx_off;                       /* next byte to send        */
static unsigned tx_total;                     /* header + payload length  */
static unsigned char __far *tx_vram;
static unsigned seq;

static void start_frame( void )
{
    static const char spin[4] = { '|', '/', '-', '\\' };
    unsigned cols = scr_cols();
    unsigned rows = scr_rows();
    unsigned bytes;
    unsigned char cr, cc;

    if( cols == 0 || cols > 132 ) cols = 80;
    if( rows == 0 || rows > 60  ) rows = 25;
    bytes   = cols * rows * 2;
    tx_vram = scr_base();
    cursor_pos( &cr, &cc );

    /* proof-of-life: tick a spinner in the top-right cell of the real
       screen, so the mirror is visibly live even at an idle prompt. */
    tx_vram[ 2 * (cols - 1) + 0 ] = spin[ seq & 3 ];
    tx_vram[ 2 * (cols - 1) + 1 ] = 0x1E;     /* yellow on blue */

    /* frame header: "DSSH", type=1(SCREEN), seq, cols, rows, curRow, curCol, len */
    hdr[0]='D'; hdr[1]='S'; hdr[2]='S'; hdr[3]='H'; hdr[4]=1;
    put16( hdr + 5, seq );
    hdr[7]=(unsigned char)cols; hdr[8]=(unsigned char)rows;
    hdr[9]=cr; hdr[10]=cc;
    put16( hdr + 11, bytes ); hdr[13]=0;

    tx_off   = 0;
    tx_total = 14 + bytes;
    seq++;
}

static void tx_pump( void )
{
    unsigned budget = TX_BUDGET;

    if( tx_off >= tx_total )
        start_frame();
    while( budget-- && tx_off < tx_total ) {
        while( (inp( U_LSR ) & 0x20) == 0 )   /* wait for TX holding empty */
            pump_rx();                        /* ... without dropping keys */
        outp( U_THR, tx_off < 14 ? hdr[tx_off] : tx_vram[tx_off - 14] );
        tx_off++;
    }
}

/* ---- resident interrupt handlers -------------------------------------- */

static volatile int in_tick;

static void __interrupt __far tick_isr( void )
{
    if( !in_tick ) {
        in_tick = 1;
        pump_rx();
        tx_pump();
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

    uart_init();
    rxlen  = 0;
    tx_off = tx_total = 0;                    /* first tick starts a frame */
    memcpy( state.magic, STATE_MAGIC, 6 );
    state.psp    = psp;
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
    printf( "DOSSHD M3 - resident console on COM1 (115200 8N1), %u KB kept.\n"
            "Screen is mirrored and remote keys injected until DOSSHD /U.\n",
            ((unsigned long)paras * 16 + 1023) / 1024 );
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
    _dos_freemem( rpsp );
    printf( "DOSSHD: uninstalled.\n" );
    return 0;
}

static int status( void )
{
    int conflict;
    struct resident_state __far *st = find_resident( &conflict );

    if( st ) {
        printf( "DOSSHD: installed, resident at %04X:0000.\n", st->psp );
        return 0;
    }
    printf( conflict ? "DOSSHD: multiplex id %02Xh is taken by another TSR.\n"
                     : "DOSSHD: not installed.\n", MPX_ID );
    return 1;
}

int main( int argc, char *argv[] )
{
    int conflict;

    if( argc > 1 ) {
        char c = argv[1][1];
        if( (argv[1][0] == '/' || argv[1][0] == '-') && argv[1][2] == '\0' ) {
            if( c == 'u' || c == 'U' ) return uninstall();
            if( c == 's' || c == 'S' ) return status();
        }
        printf( "usage: DOSSHD          install (go resident)\n"
                "       DOSSHD /S      status\n"
                "       DOSSHD /U      uninstall\n" );
        return 1;
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
