	.file	"test.c"
	.text
	.globl	a
	.section	.rodata
.LC0:
	.string	"123"
	.data
	.align 8
	.type	a, @object
	.size	a, 8
a:
	.quad	.LC0
	.globl	b
	.type	b, @object
	.size	b, 4
b:
	.string	"456"
	.globl	c
	.align 16
	.type	c, @object
	.size	c, 24
c:
	.long	10
	.long	11
	.long	12
	.long	13
	.long	14
	.long	15
	.section	.rodata
.LC1:
	.string	"fun1"
	.text
	.globl	fun1
	.type	fun1, @function
fun1:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$.LC1, %edi
	call	puts
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	fun1, .-fun1
	.globl	d
	.data
	.align 4
	.type	d, @object
	.size	d, 4
d:
	.long	5
	.section	.rodata
.LC2:
	.string	"%c %c %d\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	c+20(%rip), %ecx
	movzbl	b+2(%rip), %eax
	movsbl	%al, %edx
	movq	a(%rip), %rax
	addq	$1, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	movl	%eax, %esi
	movl	$.LC2, %edi
	movl	$0, %eax
	call	printf
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~16.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
