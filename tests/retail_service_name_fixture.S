.text
.macro site name
.globl fixture_\name
fixture_\name:
    nop
.endm
.globl fixture_run
fixture_run:
    push %rdi
    push %rsi
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $0x700, %rsp
    lea owner(%rip), %rbx
    site owner_constructed
    mov %rbx, %r14
    lea record(%rip), %r12
    lea reader(%rip), %rdx
    lea 0x100(%rsp), %rbp
    lea temporary_table(%rip), %rax
    mov %rax, 0x20(%rsp)
    lea service_name(%rip), %rax
    mov %rax, 0x68(%rsp)
    lea collection_table(%rip), %rax
    mov %rax, 0x78(%rsp)
    movl $1, 0x80(%rsp)
    lea 0x20(%rsp), %rcx
    site consumer_read
    sub $0x60, %rsp
    movl $20, 0x48(%rsp)
    lea 0x80(%rsp), %rsi
    mov %rdx, %rdi
    mov $64, %ebx
    site name_length
    sub $0xa0, %rsp
    lea 0x69(%rsp), %rbp
    lea reader(%rip), %rsi
    lea 0x178(%rsp), %r14
    movl $1, 0x77(%rbp)
    site attribute_count
    xor %edi, %edi
    movl $4, 0x67(%rbp)
    lea key_table(%rip), %rax
    mov %rax, -0x49(%rbp)
    lea type_key(%rip), %rax
    mov %rax, -0x31(%rbp)
    lea record_table(%rip), %rax
    mov %rax, -0x21(%rbp)
    lea auth_value(%rip), %rax
    mov %rax, 0xf(%rbp)
    site key_length
    site attribute_pair
    add $0x100, %rsp
    lea 0x100(%rsp), %rbp
    lea owner(%rip), %r14
    mov $1, %eax
    site parser_done
    mov %r12, 0x300(%rbp)
    lea 0x358(%r12), %rcx
    lea service_name(%rip), %rdx
    site producer_copy
    mov %rdx, 0x388(%r12)
    site producer_written
    movl $1, 0xc0(%r14)
    mov $1, %ebx
    site consumer_done
    /* Per-call gate temporary, separate from the parsed advertisement. */
    lea temporary_table(%rip), %rax
    mov %rax, 0x50(%rsp)
    lea empty_name(%rip), %rax
    mov %rax, 0x98(%rsp)
    mov %r14, %r13
    lea reader+8(%rip), %r14
    xor %esi, %esi
    site name_init
    mov $1, %eax
    site registry_count
    movl $1, -0x48(%rbp)
    site matched_count
    mov %r12, 0xd0(%rsp)
    lea 0xd0(%rsp), %rax
    site selected_source
    lea 0x50(%rsp), %rcx
    lea service_name(%rip), %rdx
    site automatic_copy
    mov %rdx, 0x98(%rsp)
    xor %eax, %eax
    site name_gate
    add $0x700, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    pop %rsi
    pop %rdi
    ret
    /* Distinct unused branch anchors: all attested before arming. */
    site preferred_lookup
    site preferred_parse
    site preferred_resolve
    site preferred_copy
    site auxiliary
#ifndef _WIN32
.section .note.GNU-stack,"",@progbits
#endif
