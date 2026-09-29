/* Entered by the Linux debugger at the getter's post-binding instruction.
 * Getter RSP is 16-byte aligned. No game instructions are overwritten. */
    .text
    .globl isac_sdk_adapter_entry
isac_sdk_adapter_entry:
    nop /* Debugger single-steps this to clear the hardware-stop bookkeeping. */
    pushfq
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    subq $128, %rsp
    movdqu %xmm0, 32(%rsp)
    movdqu %xmm1, 48(%rsp)
    movdqu %xmm2, 64(%rsp)
    movdqu %xmm3, 80(%rsp)
    movdqu %xmm4, 96(%rsp)
    movdqu %xmm5, 112(%rsp)
    movq %r14, %rcx
    movq %rbx, %rdx
    movq %rdi, %r8
    call isac_sdk_adapter_at_publication
    movdqu 32(%rsp), %xmm0
    movdqu 48(%rsp), %xmm1
    movdqu 64(%rsp), %xmm2
    movdqu 80(%rsp), %xmm3
    movdqu 96(%rsp), %xmm4
    movdqu 112(%rsp), %xmm5
    addq $128, %rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdx
    popq %rcx
    popq %rax
    popfq
    jmp *isac_sdk_adapter_resume(%rip)
