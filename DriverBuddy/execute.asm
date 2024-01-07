; execute.asm
PUBLIC DummyFunction
PUBLIC ExecAddressWithCtx

.data
origRet dq 0
origRAX dq 0
origRSP dq 0
origRBP dq 0
origR8 dq 0
origR9 dq 0
origRDX dq 0
origRCX dq 0
paramRCX dq 0

.code
DummyFunction PROC
	mov RAX, 0
	ret
DummyFunction ENDP

ExecAddressWithCtx PROC
    ; preserve current context
    
    ; integer regs
    mov [origRCX], RCX
    mov [origRDX], RDX
    mov [origR8], R8
    mov [origR9], R9
    mov [origRSP], RSP
    mov [origRBP], RBP

    ; load potential args
    mov RDX, [RCX + 88h] ; RDX = context->RDX
    mov R8, [RCX + 0B8h] ; R8 = context->R8
    mov R9, [RCX + 0C0h] ; R9 = context->R9

    ; get stack pointer
    ; mov RSP, [RCX + 98h] ; RSP = context->RSP
    
    ; save return address
    mov RAX, [RSP]
    mov [origRet], RAX

    ; mov RBP, [RCX + 0A0h] ; RBP = context->RBP
    mov RAX, [RCX + 0F8h] ; RAX = context->RIP

    ; set RCX last to get arg
    mov RCX, [RCX + 80h] ; RCX = context->RCX   

    ; RSP will now point to the original return address
    ; add RSP, 8 ; alloc for our return address
    
    ; call will push new return address on stack
    call RAX ; call the function
    ; call DummyFunction


    ; restore return address for instrumented driver
    ; sub RSP, 8
    ; mov RCX, [origRet]
    ; mov [RSP], RCX

    mov RCX, [origRCX] ; restore ctx param
    ; mov RAX, 1
    mov [RCX + 78h], RAX ; context->RAX = RAX

    ; restore our original context
    ; mov RBP, [origRBP]
    ; mov RSP, [origRSP]
    mov R9, [origR9]
    mov R8, [origR8]
    mov RDX, [origRDX]
    mov RCX, [origRCX]
   
    ret
ExecAddressWithCtx ENDP

END
