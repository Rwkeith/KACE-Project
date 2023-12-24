; CtxHandler.asm
PUBLIC ExecAddressWithCtx

.data
origRet dq 0
origRSP dq 0
origRBP dq 0
origR8 dq 0
origR9 dq 0
origRDX dq 0
origRCX dq 0
paramRCX dq 0

.code
ExecAddressWithCtx PROC
    ; preserve current context
    
    ; integer regs
    mov [origRCX], RCX
    mov [origRDX], RDX
    mov [origR8], R8
    mov [origR9], R9
    mov [origRSP], RSP
    mov [origRBP], RBP

    mov RDX, [RCX + 88h] ; RDX = context->RDX
    mov R8, [RCX + 0B8h] ; R8 = context->R8
    mov R9, [RCX + 0C0h] ; R9 = context->R9
    mov RSP, [RCX + 98h] ; RSP = context->RSP
    mov R15, [RSP]
    mov [origRet], R15

    mov RBP, [RCX + 0A0h] ; RBP = context->RBP
    mov R15, [RCX + 0F8h] ; R15 = context->RIP
    mov RCX, [RCX + 80h] ; RCX = context->RCX

    add RSP, 8 ; skip return address
    call R15 ; call the function

    mov RCX, [origRCX] ; restore ctx param
    mov [RCX + 78h], RAX ; context->RCX = RAX

    mov RBP, [origRBP]
    mov RSP, [origRSP]
    mov R9, [origR9]
    mov R8, [origR8]
    mov RDX, [origRDX]
    mov RCX, [origRCX]
   
    ret
ExecAddressWithCtx ENDP

END