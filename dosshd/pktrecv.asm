; pktrecv.asm - packet-driver receiver + staging buffer for DOSSH (net.c).
;
; The packet driver calls pkt_receiver with a FAR call, twice per frame:
;   AX = 0  request a buffer: return ES:DI = far pointer to pkt_stage
;   AX = 1  frame delivered into pkt_stage, CX = length: raise pkt_flag
; net_poll() drains pkt_stage under cli and clears pkt_flag.
;
; The receiver sets its own DS from DGROUP, so it does not depend on the
; caller's segment registers. C code that runs from the timer ISR must keep
; its working buffers static (in DGROUP), since Watcom small model addresses
; near pointers via DS and a __interrupt handler runs with SS != DS - a stack
; local passed by address would resolve to the wrong memory. See net.c.
;
; Built by Open Watcom wasm, small model, to match the C DGROUP naming
; (Watcom appends a trailing underscore to public C symbols).
;
; MIT License. Copyright (c) 2026 Sergey Subbotin.

; The SSH-enabled DOSSHD is built medium model (far code) to sit in the same
; image as the -mm crypto; assemble with -dMEDIUM_MODEL for that build so the
; C-visible routines become far calls. The default (no define) is the small
; model the base 8086 DOSSHD links, byte-for-byte unchanged.
IFDEF MEDIUM_MODEL
.model medium
ELSE
.model small
ENDIF
.8086

BS_STK_SZ       equ     4096

; Watcom C names data with a LEADING underscore and functions with a TRAILING
; underscore, so the publics below are spelled to match the C references.
.data
        public  _pkt_stage
        public  _pkt_len
        public  _pkt_flag
_pkt_stage      db  1600 dup(?)
_pkt_len        dw  0
_pkt_flag       dw  0

; send_pkt call params + a private stack for the driver's send. Crynwr-skeleton
; drivers (NE2000, PCNTPK) return CF=0 but transmit nothing when send_pkt runs
; on the tiny interrupted stack; giving the driver a real stack fixes it.
        public  _sc_int
        public  _sc_bufoff
        public  _sc_len
        public  _sc_cf
_sc_int         db  0
_sc_bufoff      dw  0
_sc_len         dw  0
_sc_cf          db  0
bs_ivt          dw  0
bs_stk          db  BS_STK_SZ dup(?)
bs_top          label byte
bs_ss           dw  0
bs_sp           dw  0

.code
        public  pkt_receiver_
pkt_receiver_   proc far
        or      ax, ax
        jne     short pr_deliver
        ; AX==0: hand the driver our staging buffer
        mov     di, offset DGROUP:_pkt_stage
        mov     ax, seg DGROUP:_pkt_stage
        mov     es, ax
        retf
pr_deliver:
        ; AX==1: frame is staged, CX = length; flag it
        push    ds
        mov     ax, DGROUP
        mov     ds, ax
        mov     word ptr _pkt_len, cx
        mov     word ptr _pkt_flag, 1
        pop     ds
        retf
pkt_receiver_   endp

; void pkt_send_bigstack(void) - issue packet-driver send_pkt (AH=4, DS:SI =
; buffer from _sc_bufoff, CX = _sc_len) at software interrupt _sc_int, run on a
; private DGROUP stack. Returns CF (0=ok,1=err) in _sc_cf. The frame buffer
; (g_txbuf) is in DGROUP, so DS already addresses it; only SS:SP is switched.
; The driver is reached through its IVT vector (rather than a fixed INT opcode),
; so it works wherever the driver installed.
;
; Interrupt state: a blind-DMA driver (AMD PCNTPK) returns immediately, but a
; blocking NDIS2 shim (DIS_PKT) does not return from send_pkt until the NIC's
; TX-complete IRQ fires. We run from the INT 1Ch timer tick, i.e. inside the
; BIOS INT 08h handler, where IRQ0 is still in service at the 8259 (its EOI is
; issued only after INT 1Ch returns) and IF is clear - so no lower-priority IRQ,
; including the NIC's, can ever be delivered and the shim deadlocks. We
; therefore issue a non-specific EOI for IRQ0 and STI around the driver call so
; the completion IRQ (and the driver's own receive upcall) can run. Re-entry of
; the TX path during this window is already prevented by the C-side in_tick
; guard (see dosshd.c) and the pkt_send `sending` guard (net.c); a nested INT
; 1Ch no-ops, and the receive upcall only touches pkt_stage, never g_txbuf. The
; BIOS INT 08h's own trailing EOI is then a harmless second non-specific EOI.
        public  pkt_send_bigstack_
IFDEF MEDIUM_MODEL
pkt_send_bigstack_ proc far
ELSE
pkt_send_bigstack_ proc near
ENDIF
        cli
        mov     bs_ss, ss             ; DS = DGROUP
        mov     bs_sp, sp
        mov     si, _sc_bufoff        ; DS:SI = frame
        mov     cx, _sc_len
        xor     ax, ax                ; IVT byte offset = _sc_int * 4
        mov     al, _sc_int
        shl     ax, 1
        shl     ax, 1
        mov     bs_ivt, ax
        mov     ax, ds                ; DGROUP
        mov     ss, ax                ; private stack in DGROUP
        mov     sp, offset DGROUP:bs_top
        push    es
        xor     ax, ax
        mov     es, ax                ; ES = 0 (IVT segment)
        mov     bx, bs_ivt
        ; Release IRQ0 at the master 8259 and enable interrupts so a blocking
        ; shim driver's TX-complete IRQ can be delivered (see header). Harmless
        ; for a blind-DMA driver, which returns before any of this matters.
        mov     al, 20h
        out     20h, al               ; non-specific EOI -> unblock lower IRQs
        mov     ah, 4                 ; send_pkt
        sti                           ; let the completion IRQ fire
        pushf                         ; simulate INT: flags (IF=1), far-call handler
        call    dword ptr es:[bx]
        pushf
        pop     ax                    ; ax = returned flags (CF = result)
        pop     es
        cli
        mov     bx, bs_ss             ; restore caller stack (ax holds flags)
        mov     ss, bx
        mov     sp, bs_sp
        and     al, 1
        mov     _sc_cf, al
        sti
        ret
pkt_send_bigstack_ endp

        end
