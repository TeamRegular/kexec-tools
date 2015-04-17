/*
 * ARM64 purgatory.
 */

.macro	debug_brk
	mov	x0, #0x18;		/* angel_SWIreason_ReportException */
	mov	x1, #0x20000;
	add	x1, x1, #0x20;		/* ADP_Stopped_BreakPoint */
	hlt	#0xf000			/* A64 semihosting */
.endm

.macro	size, sym:req
	.size \sym, . - \sym
.endm

.text

.globl purgatory_start
purgatory_start:

	adr	x19, .Lstack
	mov	sp, x19

	bl	purgatory

1:	debug_brk
	b	1b

size purgatory_start 

.align 4
	.rept	256
	.quad	0
	.endr
.Lstack:

.data

.align 3

.globl arm64_sink
arm64_sink:
	.quad	0
size arm64_sink

.globl arm64_kernel_entry
arm64_kernel_entry:
	.quad	0
size arm64_kernel_entry

.globl arm64_dtb_addr
arm64_dtb_addr:
	.quad	0
size arm64_dtb_addr

.globl arm64_kexec_lite
arm64_kexec_lite:
	.quad	0
size arm64_kexec_lite
