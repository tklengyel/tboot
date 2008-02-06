/*
 * boot.S: assembly bootstrapping code for tboot module
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <multiboot.h>
#include <config.h>
#include <msr.h>
#include <page.h>
#include <processor.h>

#define BSP_STACK_SIZE		4096
#define AP_STACK_SIZE		1024

#define cs_sel      1<<3
#define ds_sel      2<<3
#define cs16_sel    4<<3
#define ds16_sel    5<<3

	.text

ENTRY(start)
ENTRY(_start)
ENTRY(_stext)
        jmp __start

        .align 4

/* multiboot header */
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* magic number for multiboot header */
        .long MULTIBOOT_HEADER_MAGIC
        /* flags for bootloader */
        .long MULTIBOOT_HEADER_FLAGS
        /* checksum: negated sum of above */
        .long -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)


ENTRY(__start)
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:gdt_descr
        mov     $(ds_sel),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss
        ljmp    $(cs_sel),$(1f)
1:	leal	bsp_stack,%esp

        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushl   $0
        popf

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start,%edi
        mov     $_end,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Load IDT */
        lidt    idt_descr

        /* enable MCE */
        mov     %cr4,%eax
        or      $X86_CR4_MCE,%eax
        mov     %eax,%cr4

        /* pass multiboot info struct and call measured launch code */
        push    %ebx
        call    begin_launch
        ud2

/*
 * vmexit handler
 */
ENTRY(vmx_asm_vmexit_handler)
        call vmx_vmexit_handler

ENTRY(_mini_guest)
1:      hlt
        jmp 1b


#include "shutdown.S"

/*
 * entry point for GETSEC[WAKEUP]
 */
ENTRY(_txt_wakeup)
	# prepare this thread for C code
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:gdt_descr
        mov     $0x10, %ecx
        mov     %ecx, %ds
        mov     %ecx, %es
        mov     %ecx, %fs
        mov     %ecx, %gs
        mov     %ecx, %ss
        ljmp    $(cs_sel), $(1f)

        /* Load IDT */
1:	lidt    idt_descr

        /* enable MCE */
        mov     %cr4,%eax
        or      $X86_CR4_MCE,%eax
        mov     %eax,%cr4

	# get initial APIC ID for this processor
	mov	$0x01, %eax
	xor	%ebx, %ebx
	cpuid
	shr	$24, %ebx
	and	$0xff, %ebx

	# set stack as id-based offset from AP stack base
	mov	$AP_STACK_SIZE, %eax
	mul	%ebx
	sub	$AP_STACK_SIZE, %eax
	mov	$ap_stacks, %ecx
	sub	%eax, %ecx
	mov	%ecx, %esp

	push	%ebx
	call	txt_cpu_wakeup


/*
 * entry point for switch to real mode and jump
 * entry point in %ebx
 */
ENTRY(_prot_to_real)
	/* disable interrupts */
	cli
	mov     0x4(%esp), %ebx

	/* deal with parameter, real mode program entry point */
	mov     %ebx, %eax
	and     $0xffff0, %eax
	shr     $4, %eax
	mov     %ax, _real_mode_entry_point + 4
	and     $0xf, %ebx
	mov     %ebx, _real_mode_entry_point

	/* load proper segments for real mode */
	mov     $(ds16_sel), %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss
	lidt    real_idt_desc
	xor     %eax, %eax
	ljmp    $(cs16_sel), $(1f)

	.code16
1:	mov     %eax, %cr0
	mov     $0x0, %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss

	.code32

	.byte   0x66
	.byte   0x67
	ljmp    *_real_mode_entry_point

/*
 * interrupt handler
 */

int_handler:
	call handle_exception
	ud2

/*
 * descriptors and descriptor tables
 */

	.align 8

/* GDT */
gdt_descr:
	.word	gdt_table_end - gdt_table - 1
	.long	gdt_table

        .align PAGE_SIZE, 0

ENTRY(gdt_table)
		/* unused */
        .quad	0x0000000000000000
cs_descr:	/* cs */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9b00		/* read + exec + accessed */
	.word	0x00cf		/* granularity = 4096 */
ds_descr:	/* ds */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9300		/* read + write + accessed */
	.word	0x00cf		/* granularity = 4096 */
tss_descr:	/* tss */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x8900		/* system segment, 32b available TSS */
	.word	0x008f		/* granularity = 4096 */
cs16_desc:	/* cs16 */
	.word	0xffff		/* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9b00      /* read + exec + accessed */
	.word	0x008f      /* granularity = 4096, D = 0 */
ds16_desc:  /* ds16 */
	.word   0xffff      /* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9300      /* read + exec + accessed */
	.word   0x008f      /* granularity = 4096, D = 0 */
		/* end (unused) */
	.quad   0x0000000000000000
gdt_table_end:

/* IDT */
idt_descr:
	.word	idt_table_end - idt_table - 1
	.long	idt_table

	.align	8

idt_table:
	.rept 18
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_BASE_ADDR) >> 16
	.endr
	/* for machine-check exception */
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8f00   /* present, DPL=0, 32b, trap */
		.word	(int_handler - _start + TBOOT_BASE_ADDR) >> 16
	.rept 237
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_BASE_ADDR) >> 16
	.endr
idt_table_end:

/* Real Mode IDT */
real_idt_desc:
	.word   0x03ff
	.long   0

#include "wakeup.S"


/*
 * stacks
 */

.section ".bss.stack_aligned","w"

bsp_stack_end:
        .fill BSP_STACK_SIZE, 1, 0
bsp_stack:

ap_stacks_end:
        .fill AP_STACK_SIZE * (NR_CPUS-1), 1, 0
ap_stacks:


/*
 * page table and VMCS data for AP bringup
 */

        .align PAGE_SIZE, 0
.section ".bss.page_aligned","w"
ENTRY(idle_pg_table)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
ENTRY(host_vmcs)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
/* the input info when os/vmm kerneltrap into tboot */
ENTRY(ap_vmcs)
        .fill (NR_CPUS-1) * PAGE_SIZE, 1, 0
ENTRY(vmcs_end)


/*
 * misc. bss data
 */
.section ".bss"

_real_mode_entry_point:
	.long   0
	.word   0

.section ".data"

ENTRY(s3_flag)
	.long 0

/*
 * shared data page with kernel (i.e. Xen)
 * (put at end so that not split e820 region for tboot)
 */
.section ".tboot_shared","w"
        .align PAGE_SIZE, 0

ENTRY(_tboot_shared)
	.fill	PAGE_SIZE,1,0
        .align PAGE_SIZE, 0

ENTRY(_end)
