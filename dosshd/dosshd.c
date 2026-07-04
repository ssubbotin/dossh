/*
 * DOSSHD - the DOS-side server for DOSSH (https://github.com/ssubbotin/dossh)
 *
 * M1: mirror the VGA text screen out COM1 as a stream of full frames.
 *     A foreground program (no residency yet) that reads the text video
 *     buffer and streams it; a client renders it live.
 *
 * Transport for M1 is the serial port because it isolates the screen-mirror
 * logic from packet-driver / L2 networking (the next milestone). Under QEMU,
 * `-serial tcp:HOST:PORT,server` bridges COM1 to a host TCP socket the client
 * connects to.
 *
 * Build: Open Watcom, 16-bit real mode  ->  see build.sh
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <dos.h>
#include <conio.h>
#include <i86.h>
#include <stdio.h>

/* ---- COM1 16550 UART, polled ---------------------------------------- */
#define COM1      0x3F8
#define U_THR     (COM1 + 0)   /* TX holding  (DLAB=0) */
#define U_DLL     (COM1 + 0)   /* divisor low (DLAB=1) */
#define U_DLM     (COM1 + 1)   /* divisor high(DLAB=1) */
#define U_IER     (COM1 + 1)
#define U_FCR     (COM1 + 2)
#define U_LCR     (COM1 + 3)
#define U_MCR     (COM1 + 4)
#define U_LSR     (COM1 + 5)

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

static void uart_putc( int c )
{
    while( (inp( U_LSR ) & 0x20) == 0 )   /* wait for TX holding empty */
        ;
    outp( U_THR, c );
}

static void uart_write( unsigned char __far *p, unsigned n )
{
    while( n-- )
        uart_putc( *p++ );
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

/* 18.2 Hz BIOS tick counter, used to throttle the frame rate */
static unsigned long ticks( void ) { return *(unsigned long __far *)&bda[0x6C]; }

static void put16( unsigned char *b, unsigned v )
{
    b[0] = (unsigned char)(v & 0xFF);
    b[1] = (unsigned char)((v >> 8) & 0xFF);
}

int main( void )
{
    unsigned char hdr[14];
    unsigned seq = 0;
    unsigned long next;
    static const char spin[4] = { '|', '/', '-', '\\' };

    printf( "DOSSHD M1 - mirroring the text screen over COM1 (115200 8N1).\n" );
    printf( "This very screen is what the client sees. Press ESC to stop.\n" );
    uart_init();
    next = ticks();

    for( ;; ) {
        unsigned cols = scr_cols();
        unsigned rows = scr_rows();
        unsigned char __far *vram;
        unsigned char cr, cc;
        unsigned bytes, off, left;

        if( cols == 0 || cols > 132 ) cols = 80;
        if( rows == 0 || rows > 60  ) rows = 25;
        bytes = cols * rows * 2;
        vram  = scr_base();
        cursor_pos( &cr, &cc );

        /* proof-of-life: tick a spinner in the top-right cell of the real
           screen, so the mirror is visibly live even at an idle prompt. */
        vram[ 2 * (cols - 1) + 0 ] = spin[ seq & 3 ];
        vram[ 2 * (cols - 1) + 1 ] = 0x1E;            /* yellow on blue */

        /* frame header: "DSSH", type=1(SCREEN), seq, cols, rows, curRow, curCol, len */
        hdr[0]='D'; hdr[1]='S'; hdr[2]='S'; hdr[3]='H'; hdr[4]=1;
        put16( hdr + 5, seq );
        hdr[7]=(unsigned char)cols; hdr[8]=(unsigned char)rows;
        hdr[9]=cr; hdr[10]=cc;
        put16( hdr + 11, bytes ); hdr[13]=0;
        uart_write( (unsigned char __far *)hdr, 14 );

        /* payload: the raw cell array (char, attr) straight from video RAM */
        for( off = 0, left = bytes; left; ) {
            unsigned chunk = left > 512 ? 512 : left;
            uart_write( vram + off, chunk );
            off  += chunk;
            left -= chunk;
        }
        seq++;

        /* ~6 fps, and let a local ESC stop us */
        next += 3;
        while( ticks() < next ) {
            if( kbhit() && getch() == 27 ) {
                printf( "\nDOSSHD stopped.\n" );
                return 0;
            }
        }
    }
}
