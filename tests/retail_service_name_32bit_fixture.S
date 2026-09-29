/* Synthetic i386 launcher: fork, then exec the 64-bit fixture. No libc needed. */
.section .text
.global _start
_start:
    mov %esp, %ebp
    mov $174, %eax               /* i386 rt_sigaction(SIGTRAP, ...) */
    mov $5, %ebx
    mov $trap_action, %ecx
    xor %edx, %edx
    mov $8, %esi                 /* kernel sigset size, not libc's */
    int $0x80
    test %eax, %eax
    jnz failed
    int3
    pushfl
    orl $0x100, (%esp)
    popfl
    .rept 16
    nop
    .endr
    cmpl $8, trace_count
    jne failed
    cmpl $1, breakpoint_count
    jne failed
    mov $4, %eax                 /* write: observable trap-handler result */
    mov $1, %ebx
    mov $trap_message, %ecx
    mov $trap_message_end-trap_message, %edx
    int $0x80
    mov $2, %eax                 /* i386 fork */
    int $0x80
    test %eax, %eax
    js failed
    jz child
    mov %eax, %ebx
    sub $4, %esp
    mov %esp, %ecx
    xor %edx, %edx
    mov $7, %eax                 /* i386 waitpid */
    int $0x80
    mov (%esp), %ebx
    shr $8, %ebx
    mov $1, %eax
    int $0x80
child:
    mov 8(%ebp), %ebx            /* argv[1]: 64-bit fixture */
    lea 8(%ebp), %ecx            /* argv starting at argv[1] */
    mov (%ebp), %edx
    lea 8(%ebp,%edx,4), %edx     /* envp, preserving test configuration */
    mov $11, %eax                /* i386 execve */
    int $0x80
failed:
    mov $17, %ebx
    mov $1, %eax
    int $0x80
trap_handler:
    mov 8(%esp), %eax            /* siginfo_t * */
    cmpl $2, 8(%eax)             /* TRAP_TRACE */
    jne breakpoint_handler
    incl trace_count
    cmpl $8, trace_count
    jne trap_return
    mov 12(%esp), %eax           /* ucontext_t * */
    andl $0xfffffeff, 84(%eax)    /* i386 uc_mcontext.gregs[REG_EFL] */
    ret
breakpoint_handler:
    incl breakpoint_count
trap_return:
    ret
trap_restorer:
    mov $173, %eax               /* i386 rt_sigreturn */
    int $0x80
.section .data
.align 4
trap_action:
    .long trap_handler, 0x04000004, trap_restorer, 0, 0
trace_count:
    .long 0
breakpoint_count:
    .long 0
trap_message:
    .ascii "retail fixture: i386 breakpoint and trace signals preserved\n"
trap_message_end:
.section .note.GNU-stack,"",@progbits
