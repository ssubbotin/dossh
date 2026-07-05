/*
 * test_ansikey.c - native unit test for the server key map (dosshd/ansikey.c).
 *
 * ansikey.c is plain, host-portable C (its only DOS coupling is the extern
 * inject_key), so we compile it natively, stub inject_key to record the
 * (scancode, ascii) pairs it emits, feed raw terminal byte sequences, and
 * assert the injected keystrokes - covering shifted chars, Ctrl, arrows,
 * function keys, telnet CR/LF, and the lone-ESC timeout that the end-to-end
 * "type a word" tests don't reach.
 *
 * Build+run:  cc -o test_ansikey ../dosshd/ansikey.c test_ansikey.c && ./test_ansikey
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <stdio.h>
#include <string.h>
#include "../dosshd/ansikey.h"

static unsigned char got_scan[64], got_ascii[64];
static int got_n;

void inject_key( unsigned char scan, unsigned char ascii )
{
    if( got_n < 64 ) { got_scan[got_n] = scan; got_ascii[got_n] = ascii; }
    got_n++;
}

static int reboots;
void request_reboot( void ) { reboots++; }

static int failures;

/* feed a byte string, then assert exactly the expected (scan,ascii) pairs */
static void check( const char *name, const unsigned char *in, int inlen,
                   int ticks, const unsigned char *exp, int exp_pairs )
{
    int i, ok = 1;
    got_n = 0;
    for( i = 0; i < inlen; i++ ) ansi_key_byte( in[i] );
    for( i = 0; i < ticks; i++ ) ansi_key_tick();
    if( got_n != exp_pairs ) ok = 0;
    for( i = 0; ok && i < exp_pairs; i++ )
        if( got_scan[i] != exp[i * 2] || got_ascii[i] != exp[i * 2 + 1] ) ok = 0;
    if( ok ) {
        printf( "  ok   %s\n", name );
    } else {
        failures++;
        printf( "  FAIL %s: got %d pair(s):", name, got_n );
        for( i = 0; i < got_n && i < 8; i++ )
            printf( " %02x/%02x", got_scan[i], got_ascii[i] );
        printf( "\n" );
    }
}

#define IN(...)  (const unsigned char[]){ __VA_ARGS__ }
#define EXP(...) (const unsigned char[]){ __VA_ARGS__ }

int main( void )
{
    ansi_key_init();
    printf( "test_ansikey:\n" );

    /* lowercase / uppercase / digit share a scancode; ascii is verbatim */
    check( "lower a",    IN('a'), 1, 0, EXP(0x1E,'a'), 1 );
    check( "upper A",    IN('A'), 1, 0, EXP(0x1E,'A'), 1 );
    check( "digit 1",    IN('1'), 1, 0, EXP(0x02,'1'), 1 );
    check( "shift !",    IN('!'), 1, 0, EXP(0x02,'!'), 1 );
    check( "shift +",    IN('+'), 1, 0, EXP(0x0D,'+'), 1 );
    check( "space",      IN(' '), 1, 0, EXP(0x39,' '), 1 );

    /* editing / control */
    check( "Enter CR",   IN(0x0D), 1, 0, EXP(0x1C,0x0D), 1 );
    check( "Tab",        IN(0x09), 1, 0, EXP(0x0F,0x09), 1 );
    check( "Backspace DEL", IN(0x7F), 1, 0, EXP(0x0E,0x08), 1 );
    check( "Backspace BS",  IN(0x08), 1, 0, EXP(0x0E,0x08), 1 );
    check( "Ctrl-C",     IN(0x03), 1, 0, EXP(0x2E,0x03), 1 );

    /* telnet line endings collapse to a single Enter */
    check( "CR LF",      IN(0x0D,0x0A), 2, 0, EXP(0x1C,0x0D), 1 );
    check( "CR NUL",     IN(0x0D,0x00), 2, 0, EXP(0x1C,0x0D), 1 );

    /* CSI arrows / navigation: ascii 0 (extended key) */
    check( "Up",     IN(0x1B,'[','A'), 3, 0, EXP(0x48,0), 1 );
    check( "Down",   IN(0x1B,'[','B'), 3, 0, EXP(0x50,0), 1 );
    check( "Right",  IN(0x1B,'[','C'), 3, 0, EXP(0x4D,0), 1 );
    check( "Left",   IN(0x1B,'[','D'), 3, 0, EXP(0x4B,0), 1 );
    check( "Home",   IN(0x1B,'[','H'), 3, 0, EXP(0x47,0), 1 );
    check( "Delete", IN(0x1B,'[','3','~'), 4, 0, EXP(0x53,0), 1 );
    check( "PgUp",   IN(0x1B,'[','5','~'), 4, 0, EXP(0x49,0), 1 );
    check( "F5",     IN(0x1B,'[','1','5','~'), 5, 0, EXP(0x3F,0), 1 );

    /* SS3 function keys */
    check( "F1 SS3", IN(0x1B,'O','P'), 3, 0, EXP(0x3B,0), 1 );
    check( "F4 SS3", IN(0x1B,'O','S'), 3, 0, EXP(0x3E,0), 1 );

    /* lone ESC: nothing until the tick timeout, then bare ESC */
    check( "lone ESC", IN(0x1B), 1, 2, EXP(0x01,0x1B), 1 );
    /* ESC followed by a letter: ESC then the letter */
    check( "ESC then a", IN(0x1B,'a'), 2, 0, EXP(0x01,0x1B, 0x1E,'a'), 2 );

    /* warm-reboot sentinel: 0x1E x3 then Y -> request_reboot, no keys injected */
    reboots = 0; got_n = 0;
    { const unsigned char *s = IN(0x1E,0x1E,0x1E,'Y'); int i;
      for( i = 0; i < 4; i++ ) ansi_key_byte( s[i] ); }
    if( reboots == 1 && got_n == 0 )
        printf( "  ok   reboot sentinel (0x1E x3, Y)\n" );
    else { failures++; printf( "  FAIL reboot sentinel: reboots=%d keys=%d\n",
                               reboots, got_n ); }

    /* a non-Y after 0x1E x3 cancels: no reboot, and that byte injects normally */
    reboots = 0; got_n = 0;
    { const unsigned char *s = IN(0x1E,0x1E,0x1E,'a'); int i;
      for( i = 0; i < 4; i++ ) ansi_key_byte( s[i] ); }
    if( reboots == 0 && got_n == 1 && got_scan[0] == 0x1E && got_ascii[0] == 'a' )
        printf( "  ok   reboot sentinel cancels on non-Y\n" );
    else { failures++; printf( "  FAIL reboot cancel: reboots=%d keys=%d\n",
                               reboots, got_n ); }

    printf( failures ? "test_ansikey: %d FAILED\n" : "test_ansikey: all passed\n",
            failures );
    return failures ? 1 : 0;
}
