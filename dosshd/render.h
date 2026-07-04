/*
 * render.h - DOSSH ANSI screen renderer (diff-driven).
 *
 * Turns the live VGA text buffer into an ANSI byte stream a terminal renders,
 * sending only the cells that changed since the last frame. Drives both the
 * serial and network transports (the caller flushes the bytes).
 *
 * MIT License. Copyright (c) 2026 Sergey Subbotin.
 */
#ifndef DOSSH_RENDER_H
#define DOSSH_RENDER_H

/* start fresh: force a full repaint and invalidate the diff shadow (call on a
 * new connection, and once at install) */
void render_reset( void );

/* next ANSI byte to send, or -1 when there is nothing to send this tick.
 * `serial` enables the periodic full-repaint cadence (the network transport
 * repaints on connect instead). Call repeatedly, paced by the caller. */
int  render_next_byte( int serial );

/* backpressure: hand back a byte the transport could not accept, so the next
 * call returns it again */
void render_pushback( int b );

#endif
