 .text
 .globl fixture_handshake_run
fixture_handshake_run:
 pushq %rdi
 pushq %rbx
 subq $40,%rsp
 movq %rcx,%rdi
 movq %rdx,%rbx
 leaq fixture_addresses(%rip),%r10
 movl $1,%eax
 call *(%r10,%r8,8)
 addq $40,%rsp
 popq %rbx
 popq %rdi
 ret
 .globl fixture_handshake_0,fixture_handshake_1,fixture_handshake_2,fixture_handshake_3
fixture_handshake_0:
 nop
 ret
fixture_handshake_1:
 nop
 ret
fixture_handshake_2:
 nop
 ret
fixture_handshake_3:
 nop
 ret
