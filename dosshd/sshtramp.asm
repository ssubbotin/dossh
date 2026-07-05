; sshtramp.asm - run the SSH tick worker on a private DGROUP stack.
;
; The SSH crypto (ssh.c / rng.c / monocypher) is medium model: near data,
; addressed via DS. When the timer tick fires, Watcom's __interrupt prologue
; loads DS from DGROUP but SS still points at the interrupted program's stack,
; so SS != DS. Every stack-local buffer ssh.c hands to a near-data crypto
; routine would then resolve against the wrong segment. net.c avoids this by
; keeping all its ISR buffers static (DGROUP); ssh.c cannot, because its callees
; (the whole Monocypher call tree) use their own stack scratch.
;
; So for the SSH build we switch SS:SP to a private stack that lives in DGROUP
; for the duration of the SSH work, making SS == DS == DGROUP - stack locals are
; then near-correct and the crypto runs exactly as it does natively. This is the
; same private-stack trick pktrecv.asm's pkt_send_bigstack uses for the driver
; send, applied to the entire SSH computation.
;
; Built medium model (far) and linked only into the SSH-enabled DOSSHD.
;
; MIT License. Copyright (c) 2026 Sergey Subbotin.

.model medium
.8086

SSH_STK_SZ      equ     8192            ; private stack for the SSH tick worker

.data
sw_ss           dw      0
sw_sp           dw      0
sw_stk          db      SSH_STK_SZ dup(?)
sw_top          label   byte

.code
        extrn   ssh_stack_dispatch_ : far

; void ssh_run_on_stack(void) - switch SS:SP to the private DGROUP stack and call
; the C dispatcher (which runs the tick worker, or the one-time install setup),
; then restore the caller's stack. The same 8 KB stack serves both: at interrupt
; time it makes SS == DS == DGROUP for the crypto's near-data stack buffers; at
; foreground install time it simply gives ed25519 key generation a stack deep
; enough for the Monocypher call tree (the default program stack is too small).
        public  ssh_run_on_stack_
ssh_run_on_stack_ proc far
        cli
        mov     sw_ss, ss             ; save the caller's stack
        mov     sw_sp, sp
        mov     ax, ds                ; DS == DGROUP
        mov     ss, ax                ; SS = DS = DGROUP: stack locals now near-OK
        mov     sp, offset DGROUP:sw_top
        sti                           ; the callee may run with interrupts on
        call    ssh_stack_dispatch_
        cli
        mov     ss, sw_ss             ; back onto the caller's stack
        mov     sp, sw_sp
        sti
        ret
ssh_run_on_stack_ endp

        end
