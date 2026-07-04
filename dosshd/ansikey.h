/*
 * ansikey.h - map raw terminal input bytes to DOS keystrokes.
 *
 * A telnet / serial-terminal client sends raw bytes (ASCII, plus ESC-sequences
 * for arrows and function keys). This turns them into BIOS scancode/ascii pairs
 * and injects them into the keyboard ring (inject_key), so any DOS program
 * receives them as if typed locally. Replaces the old binary KEY-frame parser.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_ANSIKEY_H
#define DOSSH_ANSIKEY_H

void ansi_key_init( void );          /* build the scancode tables (call once) */
void ansi_key_byte( unsigned char b );/* feed one raw input byte */
void ansi_key_tick( void );          /* once per timer tick: flush a lone ESC */

#endif
