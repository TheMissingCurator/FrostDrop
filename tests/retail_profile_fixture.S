 .text
 .globl fixture_profile_run
fixture_profile_run:
 pushq %rdi
 pushq %rbx
 subq $40,%rsp
 movq %rcx,%rdi
 movq %rdx,%rbx
 leaq fixture_addresses(%rip),%rax
 call *(%rax,%r8,8)
 addq $40,%rsp
 popq %rbx
 popq %rdi
 ret
 .globl fixture_profile_0,fixture_profile_1,fixture_profile_2,fixture_profile_3
fixture_profile_0:
 nop
 ret
fixture_profile_1:
 nop
 ret
fixture_profile_2:
 nop
 ret
fixture_profile_3:
 nop
 ret
