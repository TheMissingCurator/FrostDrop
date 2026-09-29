    .text
    .globl fixture_publication, fixture_site, fixture_resume
fixture_publication:
    pushq %rbx
    pushq %rdi
    pushq %r14
    movq %rdi, %r14
    leaq 0x50(%rdi), %rbx
    movq %rsi, %rdi
    movq $0x12345678, %rax
    movq $0x23456789, %rcx
    movq %rax, %xmm0
fixture_site:
    nop
fixture_resume:
    cmpq $0x12345678, %rax
    jne failed
    cmpq $0x23456789, %rcx
    jne failed
    movq %xmm0, %rdx
    cmpq %rax, %rdx
    jne failed
    movq %rdi, (%rbx)
    popq %r14
    popq %rdi
    popq %rbx
    ret
failed:
    ud2
    .globl fixture_certificate, fixture_certificate_site
fixture_certificate:
    pushq %rbp
    pushq %r13
    pushq %r14
    pushq %r15
    subq $0x150, %rsp
    movq %rsp, %rbp
    movl $1, 0x140(%rbp)
    xorl %r13d, %r13d
    movl %esi, %r14d
    movl %esi, %r15d
    movl %edx, %eax
fixture_certificate_site:
    /* Exact verifier-return anchor and branch distances from the snapshot. */
    .byte 0x44,0x39,0xad,0x40,0x01,0x00,0x00,0x74,0x73,0x85,0xc0,0x7f,0x6f
    xorl %eax, %eax
    jmp certificate_return
    .org fixture_certificate_site + 0x7c, 0x90
    movl $1, %eax
certificate_return:
    addq $0x150, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %rbp
    ret
    /* Synthetic trace sites exercise four hardware slots and rotation without
       executing game code. Site signatures are relocated only by the fixture. */
    .globl fixture_version, fixture_version_site
fixture_version:
    pushq %rbx
    subq $0x40, %rsp
    movq %rdi, %rbx
    movl %esi, 0x30(%rsp)
    movl %edx, %eax
fixture_version_site:
    nop
    addq $0x40, %rsp
    popq %rbx
    ret
    .globl fixture_poll, fixture_poll_site, fixture_settings_site
fixture_poll:
    subq $0x40, %rsp
    movw %si, 0x30(%rsp)
    movl $1, %eax
fixture_poll_site:
    nop
    cmpw $7, %si
    jne poll_return
    testl %edx, %edx
    je settings_return
    movb $0, 0x53a(%rdi)
settings_return:
    movl %edx, %eax
fixture_settings_site:
    nop
poll_return:
    addq $0x40, %rsp
    ret
    .globl fixture_registration, fixture_registration_site
fixture_registration:
    movq %rdi, %rcx
    movl $1, %eax
fixture_registration_site:
    nop
    ret
    .globl fixture_error, fixture_error_site
fixture_error:
    movq %rdi, %rcx
    movl %esi, %edx
    movl $7, %eax
fixture_error_site:
    nop
    ret
    .globl fixture_frontend, fixture_frontend_site
fixture_frontend:
    pushq %rsi
    movq %rdi, %rsi
    movl $1, %eax
fixture_frontend_site:
    nop
    popq %rsi
    ret
    .globl fixture_channel, fixture_channel_site, fixture_channel_result_site
fixture_channel:
    pushq %rbp
    pushq %rbx
    pushq %r14
    pushq %r15
    pushq %r12
    movq %rdi, %rbp
    movq %rsi, %r14
    movl %edx, %r15d
    movl %ecx, %r12d
    movq $0, (%r14)
fixture_channel_site:
    nop
    movq %r8, (%r14)
    movl $1, %ebx
fixture_channel_result_site:
    nop
    movl %ebx, %eax
    popq %r12
    popq %r15
    popq %r14
    popq %rbx
    popq %rbp
    ret
    .globl fixture_getter48, fixture_getter408, fixture_getter88, fixture_getter808
fixture_getter48:
    movq 0x48(%rcx), %rax
    ret
fixture_getter408:
    movq 0x408(%rcx), %rax
    ret
fixture_getter88:
    movq 0x88(%rcx), %rax
    ret
fixture_getter808:
    movq 0x808(%rcx), %rax
    ret
    /* Numeric route fixture; checkpoint depths match the attested game stack.
       Modes 0/1/2 = empty selector / empty service name / successful creation. */
    .globl fixture_route, fixture_route_channel_site, fixture_route_channel_result_site
    .globl fixture_route_selector_count_site, fixture_route_candidate_site
    .globl fixture_route_candidate_filter_site, fixture_route_selector_iteration_site
    .globl fixture_route_selector_result_site, fixture_route_setup_site
    .globl fixture_route_transport_check_site, fixture_route_prepared_name_site
    .globl fixture_route_registration_site, fixture_route_registration_result_site
    .globl fixture_route_channel_check_site
fixture_route:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $16, %rsp
    movq %rdx, (%rsp)
    movq %rcx, 8(%rsp)
    movl %r8d, %r10d
    movq %rdi, %rbp
    movq %rsi, %r14
    xorl %r15d, %r15d
    movl $0x1001, %r12d
    movq $0, (%r14)
fixture_route_channel_site:
    nop
    subq $0xc0, %rsp
    movq %rbp, %r13
    xorl %eax, %eax
    testl %r10d, %r10d
    setne %al
fixture_route_selector_count_site:
    nop
    testl %eax, %eax
    je route_empty
    movq 0xc0(%rsp), %rbx
fixture_route_candidate_site:
    nop
    xorl %eax, %eax
fixture_route_candidate_filter_site:
    nop
    jmp route_selected
fixture_route_selector_iteration_site:
    nop
route_selected:
    addq $0xc0, %rsp
    movq (%rsp), %rax
    jmp route_selector_return
route_empty:
    addq $0xc0, %rsp
    xorl %eax, %eax
route_selector_return:
fixture_route_selector_result_site:
    nop
    testq %rax, %rax
    je route_failed
    movq 0x60(%rax), %r13
    subq $0x370, %rsp
fixture_route_setup_site:
    nop
    xorl %eax, %eax
fixture_route_transport_check_site:
    nop
    cmpl $1, %r10d
    sete %al
fixture_route_prepared_name_site:
    nop
    testl %eax, %eax
    jne route_setup_return
    subq $0x60, %rsp
    movq %r13, %rcx
fixture_route_registration_site:
    nop
    addq $0x60, %rsp
    movl $1, %eax
fixture_route_registration_result_site:
    nop
route_setup_return:
    addq $0x370, %rsp
    movq 8(%rsp), %rcx
    movq %rcx, (%r14)
    xorl %eax, %eax
    cmpl $1, %r10d
    sete %al
    testl %eax, %eax
    je route_good_object
    movl $2, 0x90(%rcx)
    movl $1, 0x94(%rcx)
    jmp route_object_check
route_good_object:
    movl $0, 0x90(%rcx)
    movl $0, 0x94(%rcx)
route_object_check:
fixture_route_channel_check_site:
    nop
    testl %eax, %eax
    jne route_failed
    movl $1, %ebx
    jmp route_return
route_failed:
    movq $0, (%r14)
    xorl %ebx, %ebx
route_return:
fixture_route_channel_result_site:
    nop
    movl %ebx, %eax
    addq $16, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
    .globl fixture_getter30, fixture_count
fixture_getter30:
    movq 0x30(%rcx), %rax
    ret
fixture_count:
    movl 8(%rcx), %eax
    ret
    .globl fixture_name_owner, fixture_name_owner_constructed_site
fixture_name_owner:
    pushq %rbx
    movq %rdi, %rbx
fixture_name_owner_constructed_site:
    nop
    popq %rbx
    ret
    .globl fixture_name_produce, fixture_name_producer_copy_site, fixture_name_producer_written_site
fixture_name_produce:
    pushq %rbp
    pushq %r14
    subq $0x410, %rsp
    leaq 0x100(%rsp), %rbp
    movq %rdi, %r14
    movq %rsi, 0x300(%rbp)
    leaq 0x358(%rsi), %rcx
fixture_name_producer_copy_site:
    nop
    movq %rdx, 0x30(%rcx)
fixture_name_producer_written_site:
    nop
    addq $0x410, %rsp
    popq %r14
    popq %rbp
    ret
    .globl fixture_name_prepare, fixture_name_name_init_site, fixture_name_registry_count_site
    .globl fixture_name_matched_count_site, fixture_name_selected_source_site
    .globl fixture_name_automatic_copy_site, fixture_name_name_gate_site
    .globl fixture_name_preferred_lookup_site, fixture_name_preferred_parse_site
    .globl fixture_name_preferred_resolve_site, fixture_name_preferred_copy_site
fixture_name_prepare:
    pushq %rbp
    pushq %r13
    pushq %rsi
    pushq %rbx
    subq $0x350, %rsp
    movq %rdi, %r13
    leaq 0x100(%rsp), %rbp
    movq %rsi, 0x50(%rsp)
    leaq 0x58(%rsp), %rax
    movq %rax, 0x98(%rsp)
    movb $0, (%rax)
    movq %rdx, 0x20(%rsp)
    xorl %esi, %esi
fixture_name_name_init_site:
    nop
    movl 0xc0(%r13), %eax
fixture_name_registry_count_site:
    nop
    testl %eax, %eax
    je fixture_name_empty
    movl $1, -0x48(%rbp)
fixture_name_matched_count_site:
    nop
    leaq 0x20(%rsp), %rax
fixture_name_selected_source_site:
    nop
    movq (%rax), %rax
    movq 0x388(%rax), %rdx
    leaq 0x50(%rsp), %rcx
fixture_name_automatic_copy_site:
    nop
    /* Legitimate fixture assignment; observer never writes it. */
    movq %rdx, 0x48(%rcx)
fixture_name_empty:
    movq 0x98(%rsp), %rdx
    xorl %eax, %eax
    cmpb $0, (%rdx)
    sete %al
fixture_name_name_gate_site:
    nop
    addq $0x350, %rsp
    popq %rbx
    popq %rsi
    popq %r13
    popq %rbp
    ret
    /* Unused preferred path anchors; unit tests exercise its actual branches. */
fixture_name_preferred_lookup_site:
    nop
fixture_name_preferred_parse_site:
    nop
fixture_name_preferred_resolve_site:
    nop
fixture_name_preferred_copy_site:
    nop
    ret
    .section .note.GNU-stack,"",@progbits
