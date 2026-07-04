/*
 * telnet.h - minimal telnet server glue for the network transport.
 *
 * On connect we proactively negotiate character mode (WILL ECHO / WILL SGA /
 * DO SGA / WILL BINARY / DO BINARY) so telnet / PuTTY send a char at a time
 * with no local echo (the mirrored screen redraw is the echo) and 8-bit clean.
 * Inbound IAC sequences are stripped from the keystroke stream and answered
 * once per option (loop-free). Only used in network mode; serial sends raw ANSI.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_TELNET_H
#define DOSSH_TELNET_H

void telnet_reset( void );           /* new connection: reset IAC state       */
void telnet_hello( void );           /* queue the proactive negotiation bytes */
void telnet_in( unsigned char b );   /* one inbound byte: strip IAC, else key  */

#endif
