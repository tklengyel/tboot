/*
 * vmcs.c: create and manage mini-VT VM for APs to handle INIT-SIPI-SIPI
 *
 * Copyright (c) 2003-2007, Intel Corporation
 * All rights reserved.
 *
 */

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <msr.h>
#include <tb_error.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <processor.h>
#include <printk.h>
#include <spinlock.h>
#include <atomic.h>
#include <uuid.h>
#include <tboot.h>
#include <txt/txt.h>
#include <txt/vmcs.h>


/* no vmexit on external intr as mini guest only handle INIT & SIPI */
#define MONITOR_PIN_BASED_EXEC_CONTROLS                 \
      (PIN_BASED_NMI_EXITING)

#define MONITOR_CPU_BASED_EXEC_CONTROLS_SUBARCH 0

#define MONITOR_VM_EXIT_CONTROLS_SUBARCH 0

/* no vmexit on hlt as guest only run this instruction */
#define MONITOR_CPU_BASED_EXEC_CONTROLS                 \
    ( MONITOR_CPU_BASED_EXEC_CONTROLS_SUBARCH |         \
      CPU_BASED_INVDPG_EXITING |                        \
      CPU_BASED_MWAIT_EXITING )

#define MONITOR_VM_EXIT_CONTROLS                        \
    ( MONITOR_VM_EXIT_CONTROLS_SUBARCH |                \
      VM_EXIT_ACK_INTR_ON_EXIT )

/* Basic flags for VM-Entry controls. */
#define MONITOR_VM_ENTRY_CONTROLS                       0x00000000

#define EXCEPTION_BITMAP_BP     (1 << 3)        /* Breakpoint */
#define EXCEPTION_BITMAP_PG     (1 << 14)       /* Page Fault */
#define MONITOR_DEFAULT_EXCEPTION_BITMAP        \
    ( EXCEPTION_BITMAP_PG |                     \
      EXCEPTION_BITMAP_BP )

#define load_TR(n)  __asm__ __volatile__ ("ltr  %%ax" : : "a" ((n)<<3) )
extern char gdt_table[];
#define RESET_TSS_DESC(n)   gdt_table[((n)<<3)+5] = 0x89

DEFINE_SPINLOCK(ap_init_lock);

/* counter for APs entering/exiting wait-for-sipi */
extern atomic_t ap_wfs_count;

/* flag for (all APs) exiting mini guest (1 = exit) */
uint32_t aps_exit_guest;

/* Dynamic (run-time adjusted) execution control flags. */
static uint32_t vmx_pin_based_exec_control;
static uint32_t vmx_cpu_based_exec_control;
static uint32_t vmx_vmexit_control;
static uint32_t vmx_vmentry_control;

static uint32_t vmcs_revision_id;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

extern char _end[];

extern void print_cr0(const char *s);
extern void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec);

extern void apply_policy(tb_error_t error);

static uint32_t adjust_vmx_controls(uint32_t ctrls, uint32_t msr)
{
    uint32_t vmx_msr_low, vmx_msr_high;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);

    /* Bit == 0 means must be zero. */
    if ( ctrls & ~vmx_msr_high )
        apply_policy(TB_ERR_FATAL);

    /* Bit == 1 means must be one. */
    ctrls |= vmx_msr_low;

    return ctrls;
}

static void vmx_init_vmcs_config(void)
{
    uint32_t vmx_msr_low, vmx_msr_high;
    uint32_t _vmx_pin_based_exec_control;
    uint32_t _vmx_cpu_based_exec_control;
    uint32_t _vmx_vmexit_control;
    uint32_t _vmx_vmentry_control;
    static int vmcs_config_init = 0;

    _vmx_pin_based_exec_control =
        adjust_vmx_controls(MONITOR_PIN_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PINBASED_CTLS_MSR);
    _vmx_cpu_based_exec_control =
        adjust_vmx_controls(MONITOR_CPU_BASED_EXEC_CONTROLS,
                            MSR_IA32_VMX_PROCBASED_CTLS_MSR);
    _vmx_vmexit_control =
        adjust_vmx_controls(MONITOR_VM_EXIT_CONTROLS,
                            MSR_IA32_VMX_EXIT_CTLS_MSR);
    _vmx_vmentry_control =
        adjust_vmx_controls(MONITOR_VM_ENTRY_CONTROLS,
                            MSR_IA32_VMX_ENTRY_CTLS_MSR);

    rdmsr(MSR_IA32_VMX_BASIC_MSR, vmx_msr_low, vmx_msr_high);

    if ( vmcs_config_init == 0 ) {
        vmcs_revision_id = vmx_msr_low;
        vmx_pin_based_exec_control = _vmx_pin_based_exec_control;
        vmx_cpu_based_exec_control = _vmx_cpu_based_exec_control;
        vmx_vmexit_control         = _vmx_vmexit_control;
        vmx_vmentry_control        = _vmx_vmentry_control;
        vmcs_config_init = 1;
    }
    else if ( (vmcs_revision_id != vmx_msr_low) ||
            (vmx_pin_based_exec_control != _vmx_pin_based_exec_control) ||
            (vmx_cpu_based_exec_control != _vmx_cpu_based_exec_control) ||
            (vmx_vmexit_control != _vmx_vmexit_control) ||
            (vmx_vmentry_control != _vmx_vmentry_control) )
        printk("vmx_init_config different on different AP.\n");

    /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
    if ( (vmx_msr_high & 0x1fff) > PAGE_SIZE ) {
        printk("vmcs size wrong.\n");
        apply_policy(TB_ERR_FATAL);
    }
}

extern uint32_t idle_pg_table[PAGE_SIZE / 4];

/* build a 1-level identity-map page table [0, _end] on AP for vmxon */
static void build_ap_pagetable(void)
{
#define PTE_FLAGS   0xe3 /* PRESENT+RW+A+D+4MB */
    uint32_t pt_entry = PTE_FLAGS;
    uint32_t *pte = &idle_pg_table[0];

    while ( pt_entry <= (uint32_t)&_end + PTE_FLAGS ) {
        *pte = pt_entry;
        pt_entry += 1 << L2_PAGETABLE_SHIFT;
        pte++;
    }
}

extern char host_vmcs[PAGE_SIZE];
extern char ap_vmcs[NR_CPUS-1][PAGE_SIZE];

static bool start_vmx(unsigned int cpuid)
{
    struct vmcs_struct *vmcs;
    static bool init_done = false;

    set_in_cr4(X86_CR4_VMXE);

    vmcs = (struct vmcs_struct *)host_vmcs;

    /* only initialize this data the first time */
    spin_lock(&ap_init_lock);

    if ( !init_done ) {
        /*printk("one-time initializing VMX mini-guest\n");*/
        memset(vmcs, 0, PAGE_SIZE);

        vmx_init_vmcs_config();
        vmcs->vmcs_revision_id = vmcs_revision_id;

        /* enable paging as required by vmentry */
        build_ap_pagetable();

        /* mark all AP VMCSes as free */
        for ( unsigned int i = 0; i < ARRAY_SIZE(ap_vmcs); i++ ) {
            ((struct vmcs_struct*)&ap_vmcs[i])->vmcs_revision_id =
                                                            ~vmcs_revision_id;
        }

        init_done = true;
    }
    spin_unlock(&ap_init_lock);

    /*printk("per-cpu initializing VMX mini-guest on cpu %u\n", cpuid);*/

    /* enable paging using 1:1 page table [0, _end] */
    /* addrs outside of tboot (e.g. MMIO) are not mapped) */
    write_cr3((unsigned long)idle_pg_table);
    set_in_cr4(X86_CR4_PSE);
    write_cr0(read_cr0() | X86_CR0_PG);

    if ( __vmxon((unsigned long)vmcs) ) {
        clear_in_cr4(X86_CR4_VMXE);
        clear_in_cr4(X86_CR4_PSE);
        write_cr0(read_cr0() & ~X86_CR0_PG);
        printk("VMXON failed for cpu %u\n", cpuid);
        return false;
    }

    printk("VMXON done for cpu %u\n", cpuid);
    return true;
}

static void stop_vmx(unsigned int cpuid)
{
    struct vmcs_struct *vmcs = NULL;

    if ( !(read_cr4() & X86_CR4_VMXE) ) {
        printk("stop_vmx() called when VMX not enabled\n");
        return;
    }

    __vmptrst((unsigned long)vmcs);

    __vmpclear((unsigned long)vmcs);

    __vmxoff();

    /* mark VMCS as free */
    vmcs->vmcs_revision_id = ~vmcs_revision_id;

    clear_in_cr4(X86_CR4_VMXE);

    /* diable paging to restore AP's state to boot xen */
    write_cr0(read_cr0() & ~X86_CR0_PG);
    clear_in_cr4(X86_CR4_PSE);
}

/* in tboot/common/boot.S */
extern void vmx_asm_vmexit_handler(void);
extern void _mini_guest(void);

/* consturct guest/host vmcs:
 * make guest vmcs from physical environment,
 * so only one binary switch between root and non-root
 */
static void construct_vmcs(void)
{
    struct __packed {
        uint16_t  limit;
        uint32_t  base;
    } xdt;
    unsigned long cr0, cr3, cr4, eflags, rsp;
    unsigned int tr;
    union vmcs_arbytes arbytes;
    uint16_t seg;

    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);
    __vmwrite(VM_EXIT_CONTROLS, vmx_vmexit_control);
    __vmwrite(VM_ENTRY_CONTROLS, vmx_vmentry_control);
    __vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmx_cpu_based_exec_control);

    /* segments selectors. */
    __asm__ __volatile__ ("mov %%ss, %0\n" : "=r"(seg));
    __vmwrite(HOST_SS_SELECTOR, seg);
    __vmwrite(GUEST_SS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%ds, %0\n" : "=r"(seg));
    __vmwrite(HOST_DS_SELECTOR, seg);
    __vmwrite(GUEST_DS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%es, %0\n" : "=r"(seg));
    __vmwrite(HOST_ES_SELECTOR, seg);
    __vmwrite(GUEST_ES_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%fs, %0\n" : "=r"(seg));
    __vmwrite(HOST_FS_SELECTOR, seg);
    __vmwrite(GUEST_FS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%gs, %0\n" : "=r"(seg));
    __vmwrite(HOST_GS_SELECTOR, seg);
    __vmwrite(GUEST_GS_SELECTOR, seg);

    __asm__ __volatile__ ("mov %%cs, %0\n" : "=r"(seg));
    __vmwrite(GUEST_CS_SELECTOR, seg);
    __vmwrite(GUEST_RIP, (uint32_t)&_mini_guest);

    __vmwrite(HOST_CS_SELECTOR, seg);
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* segment limits */
#define GUEST_SEGMENT_LIMIT     0xffffffff
    __vmwrite(GUEST_ES_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_SS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_DS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_FS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_GS_LIMIT, GUEST_SEGMENT_LIMIT);
    __vmwrite(GUEST_CS_LIMIT, GUEST_SEGMENT_LIMIT);

    /* segment AR bytes, see boot.S for details */
    arbytes.bytes = 0;
    arbytes.fields.seg_type = 0x3;          /* type = 3 */
    arbytes.fields.s = 1;                   /* code or data, i.e. not system */
    arbytes.fields.dpl = 0;                 /* DPL = 0 */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 1;    /* 32-bit */
    arbytes.fields.g = 1;

    arbytes.fields.null_bit = 0;            /* not null */
    __vmwrite(GUEST_ES_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_SS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_DS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_FS_AR_BYTES, arbytes.bytes);
    __vmwrite(GUEST_GS_AR_BYTES, arbytes.bytes);

    arbytes.fields.seg_type = 0xb;          /* type = 0xb */
    __vmwrite(GUEST_CS_AR_BYTES, arbytes.bytes);

    /* segment BASE */
    __vmwrite(GUEST_ES_BASE, 0);
    __vmwrite(GUEST_SS_BASE, 0);
    __vmwrite(GUEST_DS_BASE, 0);
    __vmwrite(GUEST_FS_BASE, 0);
    __vmwrite(GUEST_GS_BASE, 0);
    __vmwrite(GUEST_CS_BASE, 0);

    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);

    /* Guest LDT and TSS */
    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0xffff);

    __asm__ __volatile__ ("str  (%0) \n" :: "a"(&tr) : "memory");
    if ( tr == 0 )
        printk("tr is 0 on ap, may vmlaunch fail.\n");
    __vmwrite(GUEST_TR_SELECTOR, tr);
    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xffff);

    __vmwrite(HOST_TR_SELECTOR, tr);
    __vmwrite(HOST_TR_BASE, 0);


    /* tboot does not use ldt */
    arbytes.bytes = 0;
    arbytes.fields.s = 0;                   /* not code or data segement */
    arbytes.fields.seg_type = 0x2;          /* LDT */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 1;
    __vmwrite(GUEST_LDTR_AR_BYTES, arbytes.bytes);

    /* setup a TSS for vmentry as zero TR is not allowed */
    arbytes.bytes = 0;
    arbytes.fields.s = 0;          /* not code or data seg */
    arbytes.fields.seg_type = 0xb;          /* 32-bit TSS (busy) */
    arbytes.fields.p = 1;                   /* segment present */
    arbytes.fields.default_ops_size = 0;    /* 16-bit */
    arbytes.fields.g = 1;
    __vmwrite(GUEST_TR_AR_BYTES, arbytes.bytes);
    
    /* GDT */
    __asm__ __volatile__ ("sgdt (%0) \n" :: "a"(&xdt) : "memory");
    __vmwrite(GUEST_GDTR_BASE, xdt.base);
    __vmwrite(GUEST_GDTR_LIMIT, xdt.limit);
 
    __vmwrite(HOST_GDTR_BASE, xdt.base);

    /* IDT */
    __asm__ __volatile__ ("sidt (%0) \n" :: "a"(&xdt) : "memory");
    /*printk("idt.base=0x%x, limit=0x%x.\n", xdt.base, xdt.limit);*/
    __vmwrite(GUEST_IDTR_BASE, xdt.base);
    __vmwrite(GUEST_IDTR_LIMIT, xdt.limit);

    __vmwrite(HOST_IDTR_BASE, xdt.base);

    /* control registers. */
    cr0 = read_cr0();
    cr3 = read_cr3();
    cr4 = read_cr4();
    __vmwrite(HOST_CR0, cr0);
    __vmwrite(HOST_CR4, cr4);
    __vmwrite(HOST_CR3, cr3);

    __vmwrite(GUEST_CR0, cr0);
    __vmwrite(CR0_READ_SHADOW, cr0);
    __vmwrite(GUEST_CR4, cr4);
    __vmwrite(CR4_READ_SHADOW, cr4);
    __vmwrite(GUEST_CR3, cr3);

    /* debug register */
    __vmwrite(GUEST_DR7, 0);

    /* rflags & rsp */
    __save_flags(eflags);
    __vmwrite(GUEST_RFLAGS, eflags);

    __asm__ __volatile__ ("mov %%esp,%0\n\t" :"=r" (rsp));
    __vmwrite(GUEST_RSP, rsp);
    __vmwrite(HOST_RSP, rsp);

    /* MSR intercepts. */
    __vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    __vmwrite(CR0_GUEST_HOST_MASK, ~0UL);
    __vmwrite(CR4_GUEST_HOST_MASK, ~0UL);

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmwrite(CR3_TARGET_COUNT, 0);

    __vmwrite(GUEST_ACTIVITY_STATE, GUEST_STATE_ACTIVE);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);

    __vmwrite(VMCS_LINK_POINTER_HIGH, ~0UL);

    __vmwrite(EXCEPTION_BITMAP, MONITOR_DEFAULT_EXCEPTION_BITMAP);

    /*printk("vmcs setup done.\n");*/
}

static bool vmx_create_vmcs(unsigned int cpuid)
{
    struct vmcs_struct *vmcs = NULL;
    unsigned int i;

    /* find free VMCS */
    for ( i = 0; i < ARRAY_SIZE(ap_vmcs); i++ ) {
        vmcs = (struct vmcs_struct*)&ap_vmcs[i];
        if ( vmcs->vmcs_revision_id == ~vmcs_revision_id )
            break;
    }
    if ( i == ARRAY_SIZE(ap_vmcs) ) {
        printk("no free AP VMCSes\n");
        return false;
    }

    memset(vmcs, 0, PAGE_SIZE);

    vmcs->vmcs_revision_id = vmcs_revision_id;

    /* vir addr equal to phy addr as we setup identity page table */
    __vmpclear((unsigned long)vmcs);

    __vmptrld((unsigned long)vmcs);

    construct_vmcs();

    return true;
}

static void launch_mini_guest(unsigned int cpuid)
{
    unsigned long error;

    printk("launching mini-guest for cpu %u\n", cpuid);

    /* this is close enough to entering wait-for-sipi, so inc counter */
    atomic_inc(&ap_wfs_count);
    atomic_inc((atomic_t *)&_tboot_shared.num_in_wfs);

    __vmlaunch();

    /* should not reach here */
    atomic_dec(&ap_wfs_count);
    atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
    error = __vmread(VM_INSTRUCTION_ERROR);
    printk("vmlaunch failed for cpu %u, error code %lx\n", cpuid, error);
    apply_policy(TB_ERR_FATAL);
}

static void print_failed_vmentry_reason(unsigned int exit_reason)
{
    unsigned long exit_qualification;

    exit_qualification = __vmread(EXIT_QUALIFICATION);
    printk("Failed vm entry (exit reason 0x%x) ", exit_reason);
    switch ( (uint16_t)exit_reason )
        {
        case EXIT_REASON_INVALID_GUEST_STATE:
            printk("caused by invalid guest state (%ld).\n",
                   exit_qualification);
            break;
        case EXIT_REASON_MSR_LOADING:
            printk("caused by MSR entry %ld loading.\n", exit_qualification);
            break;
        case EXIT_REASON_MACHINE_CHECK:
            printk("caused by machine check.\n");
            break;
        default:
            printk("reason not known yet!");
            break;
        }
}

/* Vmexit handler for physical INIT-SIPI-SIPI from the BSP
 * Do not use printk in this critical path as BSP only
 * wait for a short time
 */
void vmx_vmexit_handler(void)
{
    unsigned int apicid = get_apicid();

    unsigned int exit_reason = __vmread(VM_EXIT_REASON);
    /*printk("vmx_vmexit_handler, exit_reason=%x.\n", exit_reason);*/

    if ( (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) ) {
        print_failed_vmentry_reason(exit_reason);
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        apply_policy(TB_ERR_FATAL);
    }
    else if ( exit_reason == EXIT_REASON_INIT ) {
        __vmwrite(GUEST_ACTIVITY_STATE, GUEST_STATE_WAIT_SIPI);
        __vmresume();
    }
    else if ( exit_reason == EXIT_REASON_SIPI ) {
        /* even though standard MP sequence is INIT-SIPI-SIPI */
        /* there is no need to wait for second SIPI (which may not */
        /* always be delivered) */
        /* but we should expect there to already have been INIT */
        /* disable VT then jump to xen code */
        unsigned long exit_qual = __vmread(EXIT_QUALIFICATION);
        uint32_t sipi_vec = (exit_qual & 0xffUL) << PAGE_SHIFT;
        /* printk("exiting due to SIPI: vector=%x\n", sipi_vec); */
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        cpu_wakeup(apicid, sipi_vec);

        /* cpu_wakeup() doesn't return, so we should never get here */
        printk("cpu_wakeup() failed\n");
        apply_policy(TB_ERR_FATAL);
    }
    else if ( exit_reason == EXIT_REASON_VMCALL ) {
        stop_vmx(apicid);
        atomic_dec(&ap_wfs_count);
        atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
        /* spin */
        while ( true )
            __asm__ __volatile__("cli; hlt;");
    }
    else {
        printk("can't handle vmexit due to 0x%x.\n", exit_reason);
        __vmresume();
    }
}

/* Launch a mini guest to handle the physical INIT-SIPI-SIPI from BSP */
void handle_init_sipi_sipi(unsigned int cpuid)
{
    if ( cpuid > NR_CPUS-1 ) {
        printk("cpuid (%u) exceeds # supported CPUs\n", cpuid);
        apply_policy(TB_ERR_FATAL);
        return;
    }
        
    /* setup a dummy tss as vmentry require a non-zero host TR */
    load_TR(3);

    /* clear the tss busy flag to avoid blocking other APs */
    RESET_TSS_DESC(3);
    
    /* prepare a guest for INIT-SIPI-SIPI handling */
    /* 1: setup VMX environment and VMXON */
    if ( !start_vmx(cpuid) ) {
        apply_policy(TB_ERR_FATAL);
        return;
    }

    /* 2: setup VMCS */
    if ( vmx_create_vmcs(cpuid) ) {

        /* 3: launch VM */
        launch_mini_guest(cpuid);
    }

    printk("control should not return here from launch_mini_guest\n");
    apply_policy(TB_ERR_FATAL);
    return;
}

void force_aps_exit(void)
{
    aps_exit_guest = 1;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
