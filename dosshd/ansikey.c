/*
 * ansikey.c - raw terminal bytes -> BIOS keystrokes (see ansikey.h).
 *
 * Ported from the reference client's key map: a US-layout scancode table, the
 * shifted-punctuation fold, and CSI/SS3 escape sequences for arrows / F-keys /
 * navigation. Extended keys inject with ascii 0, the way INT 16h reports them.
 * A lone ESC is disambiguated from an escape sequence across timer ticks.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include "ansikey.h"

/* provided by dosshd.c: poke (scancode<<8|ascii) into the BIOS type-ahead ring */
extern void inject_key( unsigned char scan, unsigned char ascii );
/* provided by dosshd.c: request a warm reboot (executed at the tick-ISR tail) */
extern void request_reboot( void );

/* ---- US-layout scancode tables (built at init) ----------------------- */
static unsigned char scan[128];      /* base char -> scancode-set-1 make code */
static unsigned char unshift[128];   /* shifted char -> its unshifted char    */

void ansi_key_init( void )
{
    static const char *rows[4] = {
        "1234567890-=", "qwertyuiop[]", "asdfghjkl;'`", "\\zxcvbnm,./"
    };
    static const unsigned char base[4] = { 0x02, 0x10, 0x1E, 0x2B };
    static const char *sh = "!@#$%^&*()_+{}:\"~<>?|";
    static const char *ba = "1234567890-=[];'`,./\\";
    int r, i;

    for( r = 0; r < 4; r++ )
        for( i = 0; rows[r][i]; i++ )
            scan[(unsigned char)rows[r][i]] = (unsigned char)( base[r] + i );
    scan[' '] = 0x39;
    for( i = 0; sh[i]; i++ )
        unshift[(unsigned char)sh[i]] = (unsigned char)ba[i];
}

/* ---- single printable / control byte --------------------------------- */
static void map_byte( unsigned char b )
{
    unsigned char base, sc;
    if( b == 0x0D || b == 0x0A ) { inject_key( 0x1C, 0x0D ); return; }  /* Enter */
    if( b == 0x09 )              { inject_key( 0x0F, 0x09 ); return; }  /* Tab   */
    if( b == 0x7F || b == 0x08 ) { inject_key( 0x0E, 0x08 ); return; }  /* Bksp  */
    if( b >= 32 && b < 127 ) {
        base = unshift[b];
        if( !base ) base = ( b >= 'A' && b <= 'Z' ) ? (unsigned char)( b + 32 ) : b;
        sc = scan[base];
        if( sc ) inject_key( sc, b );
        return;
    }
    if( b >= 1 && b <= 26 ) {                       /* Ctrl-A .. Ctrl-Z */
        sc = scan[b + 96];
        if( sc ) inject_key( sc, b );
    }
}

/* ---- extended keys (arrows, F-keys, navigation): ascii 0 ------------- */
static unsigned char csi_final( unsigned char f )
{
    switch( f ) {
    case 'A': return 0x48;  case 'B': return 0x50;   /* up / down   */
    case 'C': return 0x4D;  case 'D': return 0x4B;   /* right / left*/
    case 'H': return 0x47;  case 'F': return 0x4F;   /* home / end  */
    }
    return 0;
}
static unsigned char csi_tilde( unsigned n )
{
    switch( n ) {
    case 1: return 0x47;  case 2: return 0x52;  case 3: return 0x53;
    case 4: return 0x4F;  case 5: return 0x49;  case 6: return 0x51;
    case 11: return 0x3B; case 12: return 0x3C; case 13: return 0x3D;
    case 14: return 0x3E; case 15: return 0x3F; case 17: return 0x40;
    case 18: return 0x41; case 19: return 0x42; case 20: return 0x43;
    case 21: return 0x44; case 23: return 0x57; case 24: return 0x58;
    }
    return 0;
}
static unsigned char ss3_final( unsigned char f )
{
    switch( f ) {
    case 'P': return 0x3B; case 'Q': return 0x3C;   /* F1 / F2 */
    case 'R': return 0x3D; case 'S': return 0x3E;   /* F3 / F4 */
    case 'H': return 0x47; case 'F': return 0x4F;
    }
    return 0;
}

/* ---- escape-sequence assembly (across bytes and ticks) --------------- */
static unsigned char pend[12];
static int pendlen;
static int pend_age;
static int swallow;      /* after CR, swallow a following LF/NUL */
static int rb_state;     /* warm-reboot sentinel: count of leading 0x1E bytes */

static void finish_csi( unsigned char final )
{
    unsigned char sc;
    if( final == '~' ) {
        unsigned n = 0, i;
        for( i = 2; i < (unsigned)pendlen; i++ )
            if( pend[i] >= '0' && pend[i] <= '9' )
                n = n * 10 + ( pend[i] - '0' );
            else
                break;
        sc = csi_tilde( n );
    } else {
        sc = csi_final( final );
    }
    if( sc ) inject_key( sc, 0 );
}

void ansi_key_byte( unsigned char b )
{
    /* Warm-reboot sentinel: three Ctrl-^ (0x1E) then Y/y. 0x1E is dropped by
       map_byte (it never reaches DOS), so reserving it costs no keystroke, and
       three-in-a-row plus a Y confirm can't be fat-fingered by accident. */
    if( b == 0x1E ) {
        if( rb_state < 3 ) rb_state++;
        return;
    }
    if( rb_state >= 3 ) {
        rb_state = 0;
        if( b == 'Y' || b == 'y' ) { request_reboot(); return; }
        /* anything else cancels; fall through and handle b normally */
    } else {
        rb_state = 0;
    }

    if( swallow ) {                       /* CR was just sent */
        swallow = 0;
        if( b == 0x0A || b == 0x00 ) return;   /* swallow the paired LF/NUL */
    }
    if( pendlen == 0 ) {
        if( b == 0x1B ) { pend[0] = 0x1B; pendlen = 1; pend_age = 0; return; }
        if( b == 0x0D ) { inject_key( 0x1C, 0x0D ); swallow = 1; return; }
        map_byte( b );
        return;
    }
    pend_age = 0;
    if( pendlen == 1 ) {                   /* just after ESC */
        if( b == '[' || b == 'O' ) { pend[pendlen++] = b; return; }
        inject_key( 0x01, 0x1B );          /* ESC + other: lone ESC, then b */
        pendlen = 0;
        ansi_key_byte( b );
        return;
    }
    if( pend[1] == '[' ) {                 /* CSI: ESC [ params final */
        if( ( b >= '0' && b <= '9' ) || b == ';' ) {
            if( pendlen < (int)sizeof( pend ) ) pend[pendlen++] = b;
            return;
        }
        finish_csi( b );
        pendlen = 0;
        return;
    }
    if( pend[1] == 'O' ) {                 /* SS3: ESC O final */
        unsigned char sc = ss3_final( b );
        if( sc ) inject_key( sc, 0 );
        pendlen = 0;
        return;
    }
    pendlen = 0;
}

void ansi_key_tick( void )
{
    if( pendlen > 0 && ++pend_age >= 2 ) {     /* ~110 ms with no continuation */
        if( pendlen == 1 ) inject_key( 0x01, 0x1B );   /* it was a lone ESC */
        pendlen = 0;
    }
}
