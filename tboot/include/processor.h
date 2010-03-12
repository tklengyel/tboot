
/* Portions are: Copyright (c) 1994 Linus Torvalds */

#ifndef __ASM_X86_PROCESSOR_H
#define __ASM_X86_PROCESSOR_H

/*
 * CPU vendor IDs
 */
#define X86_VENDOR_INTEL 0
#define X86_VENDOR_CYRIX 1
#define X86_VENDOR_AMD 2
#define X86_VENDOR_UMC 3
#define X86_VENDOR_NEXGEN 4
#define X86_VENDOR_CENTAUR 5
#define X86_VENDOR_RISE 6
#define X86_VENDOR_TRANSMETA 7
#define X86_VENDOR_NSC 8
#define X86_VENDOR_NUM 9
#define X86_VENDOR_UNKNOWN 0xff

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_CF	0x00000001 /* Carry Flag */
#define X86_EFLAGS_PF	0x00000004 /* Parity Flag */
#define X86_EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define X86_EFLAGS_ZF	0x00000040 /* Zero Flag */
#define X86_EFLAGS_SF	0x00000080 /* Sign Flag */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define X86_EFLAGS_OF	0x00000800 /* Overflow Flag */
#define X86_EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define X86_EFLAGS_NT	0x00004000 /* Nested Task */
#define X86_EFLAGS_RF	0x00010000 /* Resume Flag */
#define X86_EFLAGS_VM	0x00020000 /* Virtual Mode */
#define X86_EFLAGS_AC	0x00040000 /* Alignment Check */
#define X86_EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define X86_EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define X86_EFLAGS_ID	0x00200000 /* CPUID detection flag */

/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001 /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002 /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004 /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008 /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010 /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020 /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000 /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000 /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000 /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000 /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000 /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001	/* enable vm86 extensions */
#define X86_CR4_PVI		0x0002	/* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004	/* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008	/* enable debugging extensions */
#define X86_CR4_PSE		0x0010	/* enable page size extensions */
#define X86_CR4_PAE		0x0020	/* enable physical address extensions */
#define X86_CR4_MCE		0x0040	/* Machine check enable */
#define X86_CR4_PGE		0x0080	/* enable global pages */
#define X86_CR4_PCE		0x0100	/* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200	/* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400	/* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */
#define X86_CR4_SMXE        0x4000  /* enable SMX */

/*
 * Trap/fault mnemonics.
 */
#define TRAP_divide_error      0
#define TRAP_debug             1
#define TRAP_nmi               2
#define TRAP_int3              3
#define TRAP_overflow          4
#define TRAP_bounds            5
#define TRAP_invalid_op        6
#define TRAP_no_device         7
#define TRAP_double_fault      8
#define TRAP_copro_seg         9
#define TRAP_invalid_tss      10
#define TRAP_no_segment       11
#define TRAP_stack_error      12
#define TRAP_gp_fault         13
#define TRAP_page_fault       14
#define TRAP_spurious_int     15
#define TRAP_copro_error      16
#define TRAP_alignment_check  17
#define TRAP_machine_check    18
#define TRAP_simd_error       19
#define TRAP_deferred_nmi     31

/* Set for entry via SYSCALL. Informs return code to use SYSRETQ not IRETQ. */
/* NB. Same as VGCF_in_syscall. No bits in common with any other TRAP_ defn. */
#define TRAP_syscall         256

/*
 * Non-fatal fault/trap handlers return an error code to the caller. If the
 * code is non-zero, it means that either the exception was not due to a fault
 * (i.e., it was a trap) or that the fault has been fixed up so the instruction
 * replay ought to succeed.
 */
#define EXCRET_not_a_fault 1 /* It was a trap. No instruction replay needed. */
#define EXCRET_fault_fixed 1 /* It was fault that we fixed: try a replay. */

/* 'trap_bounce' flags values */
#define TBF_EXCEPTION          1
#define TBF_EXCEPTION_ERRCODE  2
#define TBF_INTERRUPT          8
#define TBF_FAILSAFE          16

/* 'arch_vcpu' flags values */
#define _TF_kernel_mode        0
#define TF_kernel_mode         (1<<_TF_kernel_mode)

/* #PF error code values. */
#define PFEC_page_present   (1U<<0)
#define PFEC_write_access   (1U<<1)
#define PFEC_user_mode      (1U<<2)
#define PFEC_reserved_bit   (1U<<3)
#define PFEC_insn_fetch     (1U<<4)

#ifndef __ASSEMBLY__

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
#define cpuid(_op,_eax,_ebx,_ecx,_edx)          \
    __asm__ __volatile__ ("cpuid"                             \
                          : "=a" (*(int *)(_eax)),            \
                            "=b" (*(int *)(_ebx)),            \
                            "=c" (*(int *)(_ecx)),            \
                            "=d" (*(int *)(_edx))             \
                          : "0" (_op), "2" (0))

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(
    int op,
    int count,
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx)
{
    __asm__ __volatile__ ("cpuid"
                          : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                          : "0" (op), "c" (count));
}

/*
 * CPUID functions returning a single datum
 */
static always_inline unsigned int cpuid_eax(unsigned int op)
{
    unsigned int eax;

    __asm__ __volatile__ ("cpuid"
                          : "=a" (eax)
                          : "0" (op)
                          : "bx", "cx", "dx");
    return eax;
}
static always_inline unsigned int cpuid_ebx(unsigned int op)
{
    unsigned int eax, ebx;

    __asm__ __volatile__ ("cpuid"
                          : "=a" (eax), "=b" (ebx)
                          : "0" (op)
                          : "cx", "dx" );
    return ebx;
}
static always_inline unsigned int cpuid_ecx(unsigned int op)
{
    unsigned int eax, ecx;

    __asm__ __volatile__ ("cpuid"
                          : "=a" (eax), "=c" (ecx)
                          : "0" (op)
                          : "bx", "dx" );
    return ecx;
}
static always_inline unsigned int cpuid_edx(unsigned int op)
{
    unsigned int eax, edx;

    __asm__ __volatile__ ("cpuid"
                          : "=a" (eax), "=d" (edx)
                          : "0" (op)
                          : "bx", "cx");
    return edx;
}



static inline unsigned long read_cr0(void)
{
    unsigned long __cr0;
    __asm__ __volatile__ ("mov %%cr0,%0\n\t" :"=r" (__cr0));
    return __cr0;
}

static inline void write_cr0(unsigned long val)
{
    __asm__ __volatile__ ("mov %0,%%cr0": :"r" ((unsigned long)val));
}

static inline unsigned long read_cr2(void)
{
    unsigned long __cr2;
    __asm__ __volatile__ ("mov %%cr2,%0\n\t" :"=r" (__cr2));
    return __cr2;
}

static inline unsigned long read_cr4(void)
{
    unsigned long __cr4;
    __asm__ __volatile__ ("mov %%cr4,%0\n\t" :"=r" (__cr4));
    return __cr4;
}

static inline void write_cr4(unsigned long val)
{
	__asm__ __volatile__ ("mov %0,%%cr4": :"r" ((unsigned long)val));
}

/* Read pagetable base. */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ ("mov %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

static inline void write_cr3(unsigned long cr3)
{
    __asm__ __volatile__ ( "mov %0, %%cr3" : : "r" (cr3) : "memory" );
}

static always_inline void set_in_cr4 (unsigned long mask)
{
    unsigned long dummy;
    __asm__ __volatile__ (
        "mov %%cr4,%0\n\t"
        "or %1,%0\n\t"
        "mov %0,%%cr4\n"
        : "=&r" (dummy) : "irg" (mask) );
}

static always_inline void clear_in_cr4 (unsigned long mask)
{
    unsigned long dummy;
    __asm__ __volatile__ (
        "mov %%cr4,%0\n\t"
        "and %1,%0\n\t"
        "mov %0,%%cr4\n"
        : "=&r" (dummy) : "irg" (~mask) );
}

/* Clear and set 'TS' bit respectively */
static inline void clts(void)
{
    __asm__ __volatile__ ("clts");
}

static inline void stts(void)
{
    write_cr0(X86_CR0_TS|read_cr0());
}


/* Stop speculative execution */
static inline void sync_core(void)
{
    int tmp;
    __asm__ __volatile__ ("cpuid" : "=a" (tmp) : "0" (1)
                          : "ebx","ecx","edx","memory");
}

static always_inline void __monitor(const void *eax, unsigned long ecx,
		unsigned long edx)
{
	/* "monitor %eax,%ecx,%edx;" */
	__asm__ __volatile__ (
		".byte 0x0f,0x01,0xc8;"
		: :"a" (eax), "c" (ecx), "d"(edx));
}

static always_inline void __mwait(unsigned long eax, unsigned long ecx)
{
	/* "mwait %eax,%ecx;" */
	__asm__ __volatile__ (
		".byte 0x0f,0x01,0xc9;"
		: :"a" (eax), "c" (ecx));
}

/* REP NOP (PAUSE) is a good thing to insert into busy-wait loops. */
static always_inline void rep_nop(void)
{
    __asm__ __volatile__ ( "rep;nop" : : : "memory" );
}

#define cpu_relax() rep_nop()

static inline unsigned int get_apicid(void)
{
    return cpuid_ebx(1) >> 24;
}

#endif /* __ASSEMBLY__ */

#endif /* __ASM_X86_PROCESSOR_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
