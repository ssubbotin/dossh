/*
 * render.c - DOSSH ANSI screen renderer.
 *
 * Each tick, one pass over the live VGA text buffer (0xB800 / 0xB000 for mono)
 * compares it to a shadow of the last frame and emits ANSI for the changed
 * cells only: a CUP (ESC[row;colH) to move, an SGR when the VGA attribute
 * changes, and the CP437 character as UTF-8. A full repaint (clear + every
 * cell) is sent on reset, on a geometry change, on a serial-only ~2 s cadence
 * (so a terminal attaching mid-stream resynchronises), and when most of the
 * screen changed (CLS/scroll). Output is produced in bounded chunks so the
 * caller can pace it; a large repaint resumes across ticks.
 *
 * The whole path is DOS-call-free (far memory + a UTF-8 table), so it is safe
 * from the timer ISR.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <dos.h>
#include <i86.h>
#include "cp437.h"
#include "render.h"

/* ---- screen scrape (BIOS Data Area, segment 0x40) -------------------- */
static unsigned char __far *bda = (unsigned char __far *)MK_FP( 0x40, 0 );

static unsigned scr_cols( void ) { return bda[0x4A]; }        /* # columns    */
static unsigned scr_rows( void ) { return bda[0x84] + 1; }    /* rows-1 (EGA+) */
static unsigned char scr_mode( void ) { return bda[0x49]; }   /* video mode   */

static unsigned char __far *scr_base( void )
{
    return (scr_mode() == 7) ? (unsigned char __far *)MK_FP( 0xB000, 0 )
                             : (unsigned char __far *)MK_FP( 0xB800, 0 );
}
/* returns the page-0 cursor as (row<<8)|col. NOTE: returns by value, not via
 * pointers - this runs in the timer ISR where SS != DS, so passing &local to a
 * function that dereferences it (Watcom small model, DS-relative) would write
 * garbage into DGROUP. */
static unsigned cursor_rc( void )
{
    return *(unsigned __far *)&bda[0x50];   /* low byte = col, high byte = row */
}
static int cursor_visible( void )
{
    /* cursor "type" at 0040:0060: high byte = start scanline; bit 5 => off */
    unsigned t = *(unsigned __far *)&bda[0x60];
    return ((t >> 8) & 0x20) == 0;
}
static unsigned long ticks( void ) { return *(unsigned long __far *)&bda[0x6C]; }

/* ---- output buffer + emit helpers ------------------------------------ */
#define OBUF 2048
static unsigned char obuf[OBUF];
static unsigned o_len, o_off;
static int pushed = -1;

static void e_b( unsigned char c ) { if( o_len < OBUF ) obuf[o_len++] = c; }
static void e_s( const char *s )   { while( *s ) e_b( (unsigned char)*s++ ); }
static void e_num( unsigned v )
{
    unsigned char t[6]; int n = 0;
    if( !v ) { e_b( '0' ); return; }
    while( v ) { t[n++] = (unsigned char)('0' + v % 10); v /= 10; }
    while( n ) e_b( t[--n] );
}
static void e_cup( unsigned row, unsigned col )
{
    e_s( "\x1b[" ); e_num( row + 1 ); e_b( ';' ); e_num( col + 1 ); e_b( 'H' );
}
static void e_sgr( unsigned char attr )
{
    static const unsigned char v2a[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
    unsigned fg = attr & 0x0F, bg = (attr >> 4) & 0x07;
    unsigned fgc = fg < 8 ? 30 + v2a[fg] : 90 + v2a[fg - 8];
    e_s( "\x1b[0;" ); e_num( fgc ); e_b( ';' ); e_num( 40 + v2a[bg] );
    if( attr & 0x80 ) e_s( ";5" );       /* VGA blink bit -> SGR blink */
    e_b( 'm' );
}
static void e_char( unsigned char ch )
{
    const unsigned char *u = cp437_utf8[ch];
    unsigned i, n = u[0];
    for( i = 1; i <= n; i++ ) e_b( u[i] );
}

/* ---- diff / repaint state -------------------------------------------- */
#define SHADOW_BYTES 4000            /* 80x25; larger modes -> periodic repaint */
static unsigned char shadow[SHADOW_BYTES];
static int shadow_valid;
static unsigned sh_cols, sh_rows;
static int force_kf = 1;
static unsigned long last_kf;

static int frame_active, is_repaint, is_toobig;
static unsigned walk_cell, total_cells, f_cols;
static int last_emit, cur_sgr;
static unsigned char last_cur_r = 255, last_cur_c = 255;

#define CADENCE_TICKS 36             /* ~2 s at 18.2 Hz */

void render_reset( void )
{
    shadow_valid = 0; force_kf = 1; frame_active = 0;
    o_len = o_off = 0; pushed = -1;
    cur_sgr = -1; last_emit = -2; last_cur_r = last_cur_c = 255;
}

/* decide whether to start a frame this fill, and of what kind */
static void frame_decide( int serial )
{
    unsigned cols = scr_cols(), rows = scr_rows();
    unsigned char __far *v;
    unsigned c, bytes, changed = 0, rc;
    int repaint, clear;
    (void)serial;

    if( cols == 0 || cols > 132 ) cols = 80;
    if( rows == 0 || rows > 60  ) rows = 25;
    bytes = cols * rows * 2;
    v = scr_base();
    is_toobig = ( bytes > SHADOW_BYTES );

    /* A hard clear (ESC[2J) is only for a new connection or a geometry change. */
    clear = force_kf || !shadow_valid || cols != sh_cols || rows != sh_rows;
    repaint = clear;
    /* Periodic full repaint on BOTH transports: re-emit every cell WITHOUT a
       clear (so no flicker - repainting identical content is invisible, but it
       paints over any stale cell). This self-heals a screen left garbled by a
       dropped connect-repaint on a lossy link, which a pure diff never fixes. */
    if( !repaint && (long)( ticks() - last_kf ) >= CADENCE_TICKS )
        repaint = 1;
    if( is_toobig )                  /* no shadow to diff: only full frames */
        clear = repaint = force_kf
                        || ( (long)( ticks() - last_kf ) >= CADENCE_TICKS );

    /* large modes have no shadow to diff against (bytes > SHADOW_BYTES); between
       cadence repaints there is nothing to send - and diffing here would read
       past the 4000-byte shadow. */
    if( is_toobig && !repaint )
        return;

    if( !repaint ) {                 /* diff: is anything worth sending? */
        for( c = 0; c < bytes; c += 2 )
            if( v[c] != shadow[c] || v[c + 1] != shadow[c + 1] ) changed++;
        rc = cursor_rc();
        if( changed == 0 && (unsigned char)(rc >> 8) == last_cur_r
                         && (unsigned char)rc == last_cur_c )
            return;                  /* idle - send nothing */
        if( changed * 4 > ( bytes / 2 ) * 3 )   /* >75% cells -> soft repaint */
            repaint = 1;
    }

    f_cols = cols; total_cells = cols * rows;
    is_repaint = repaint; walk_cell = 0;
    last_emit = -2; cur_sgr = -1; frame_active = 1;
    e_s( "\x1b[?25l" );              /* hide cursor while painting */
    if( clear )
        e_s( "\x1b[2J\x1b[H" );
    if( repaint ) {
        sh_cols = cols; sh_rows = rows;
    }
}

/* emit changed cells into obuf until it is near full or the frame is done */
static void frame_fill( void )
{
    unsigned char __far *v = scr_base();
    unsigned c = walk_cell, total = total_cells, cols = f_cols;

    while( c < total ) {
        unsigned idx = c * 2;
        unsigned char ch, at;
        int changed;
        /* reserve room for one worst-case cell (~24B) AND the frame tail
           (park cursor + show, ~20B) so completion is never truncated */
        if( o_len + 48 > OBUF ) break;
        ch = v[idx]; at = v[idx + 1];
        changed = is_repaint || is_toobig
                  || ch != shadow[idx] || at != shadow[idx + 1];
        if( changed ) {
            unsigned col = c % cols;
            if( (int)c != last_emit + 1 || col == 0 )
                e_cup( c / cols, col );
            if( (int)at != cur_sgr ) { e_sgr( at ); cur_sgr = at; }
            e_char( ch );
            if( !is_toobig ) { shadow[idx] = ch; shadow[idx + 1] = at; }
            last_emit = (int)c;
        }
        c++;
    }
    walk_cell = c;

    if( c >= total ) {               /* frame complete */
        unsigned rc = cursor_rc();
        unsigned char cr = (unsigned char)( rc >> 8 ), cc = (unsigned char)rc;
        e_cup( cr, cc );
        e_s( cursor_visible() ? "\x1b[?25h" : "\x1b[?25l" );
        last_cur_r = cr; last_cur_c = cc;
        frame_active = 0;
        if( !is_toobig ) shadow_valid = 1;
        if( is_repaint ) force_kf = 0;
        if( is_repaint || is_toobig ) last_kf = ticks();
    }
}

int render_next_byte( int serial )
{
    if( pushed >= 0 ) { int b = pushed; pushed = -1; return b; }
    if( o_off < o_len ) return obuf[o_off++];
    o_len = o_off = 0;                /* refill */
    if( !frame_active ) frame_decide( serial );
    if( frame_active ) frame_fill();
    if( o_off < o_len ) return obuf[o_off++];
    return -1;
}

void render_pushback( int b ) { pushed = b; }
