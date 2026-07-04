/*
 * VIDTEST - a deliberately low-level DOS app for DOSSH testing and demos.
 *
 * It writes its output STRAIGHT to VGA text memory (no DOS or BIOS output
 * calls) and reads the keyboard with INT 16h AH=00h - the way BIOS
 * flashers, installers and other firmware-era tools behave. A pipe-based
 * remote console sees none of this; DOSSH must mirror and drive it.
 *
 * Build: Open Watcom, 16-bit real mode  ->  see ../dosshd/build.sh
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#include <i86.h>
#include <stdio.h>

static void vputs( unsigned row, const char *s, unsigned char attr )
{
    unsigned char __far *p =
        (unsigned char __far *)MK_FP( 0xB800, row * 80 * 2 );
    while( *s ) {
        *p++ = (unsigned char)*s++;
        *p++ = attr;
    }
}

int main( void )
{
    union REGS r;
    char line[81];

    vputs( 5, " VIDTEST: writing straight to B800:0 - no DOS/BIOS output calls ",
           0x4F );
    vputs( 6, " keys are read via INT 16h and echoed below; 'q' quits ",
           0x4E );
    for( ;; ) {
        r.h.ah = 0x00;                       /* BIOS: wait for keystroke */
        int86( 0x16, &r, &r );
        sprintf( line, " KEY: %c  ascii=0x%02X scan=0x%02X ",
                 (r.h.al >= 32 && r.h.al < 127) ? r.h.al : '.',
                 r.h.al, r.h.ah );
        vputs( 7, line, 0x2F );
        if( r.h.al == 'q' )
            break;
    }
    return 0;
}
