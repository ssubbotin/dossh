/*
 * telnet.h - minimal telnet server glue for the network transport.
 *
 * On connect we proactively negotiate character mode (WILL ECHO / WILL SGA /
 * DO SGA / WILL BINARY / DO BINARY) so telnet / PuTTY send a char at a time
 * with no local echo (the mirrored screen redraw is the echo) and 8-bit clean.
 * Inbound IAC sequences are stripped from the keystroke stream and answered
 * once per option (loop-free). Only used in network mode; serial sends raw ANSI.
 * State is kept per client slot (0..NCONN-1) so several clients negotiate
 * independently while sharing one screen.
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_TELNET_H
#define DOSSH_TELNET_H

void telnet_reset( int slot );          /* new connection: reset slot IAC state  */
void telnet_hello( int slot );          /* queue the proactive negotiation bytes */
void telnet_in( int slot, unsigned char b ); /* one inbound byte: strip IAC, else key */

#endif
