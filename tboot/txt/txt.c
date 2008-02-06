/*
 * txt.c: Intel(r) TXT support functions, including initiating measured
 *        launch, post-launch, AP wakeup, etc.
 *
 * Copyright (c) 2003-2007, Intel Corporation
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

#include <config.h>
#include <stdbool.h>
#include <types.h>
#include <tb_error.h>
#include <multiboot.h>
#include <msr.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <processor.h>
#include <printk.h>
#include <atomic.h>
#include <tpm.h>
#include <e820.h>
#include <uuid.h>
#include <elf.h>
#include <tboot.h>
#include <mle.h>
#define LCP_UUID_ONLY
#include <lcp.h>
#include <txt/txt.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/acmod.h>
#include <txt/mtrrs.h>
#include <txt/smx.h>
#include <txt/verify.h>
#include <txt/vmcs.h>

/* counter timeout for waiting for all APs to enter wait-for-sipi */
#define AP_WFS_TIMEOUT     0x20000000

extern char _start[];           /* start of module */
extern char _end[];             /* end of module */
extern char _mle_start[];       /* start of text section */
extern char _mle_end[];         /* end of text section */
extern char __start[];          /* tboot entry point in boot.S */
extern char _txt_wakeup[];      /* RLP join address for GETSEC[WAKEUP] */

/*
 * this is the structure whose addr we'll put in TXT heap
 * it needs to be within the MLE pages, so force it to the .text section
 */
static __attribute__ ((__section__ (".text"))) const mle_hdr_t g_mle_hdr = {
    guid              :  MLE_HDR_GUID,
    length            :  sizeof(mle_hdr_t),
    version           :  0x00010001,
    entry_point       :  (uint32_t)&__start - TBOOT_BASE_ADDR,
    first_valid_page  :  0,
    mle_start_off     :  (uint32_t)&_mle_start - TBOOT_BASE_ADDR,
    mle_end_off       :  (uint32_t)&_mle_end - TBOOT_BASE_ADDR,
};

/*
 * counts of APs going into wait-for-sipi
 */
/* count of APs in WAIT-FOR-SIPI */
atomic_t ap_wfs_count;

static void print_file_info(void)
{
    printk("file addresses:\n");
    printk("\t &_start=%p\n", &_start);
    printk("\t &_end=%p\n", &_end);
    printk("\t &_mle_start=%p\n", &_mle_start);
    printk("\t &_mle_end=%p\n", &_mle_end);
    printk("\t &__start=%p\n", &__start);
    printk("\t &_txt_wakeup=%p\n", &_txt_wakeup);
    printk("\t &g_mle_hdr=%p\n", &g_mle_hdr);
}

static void print_mle_hdr(const mle_hdr_t *mle_hdr)
{
    printk("MLE header:\n");
    printk("\t guid="); print_uuid((uuid_t *)mle_hdr->guid); printk("\n");
    printk("\t length=%x\n", mle_hdr->length);
    printk("\t version=%08x\n", mle_hdr->version);
    printk("\t entry_point=%08x\n", mle_hdr->entry_point);
    printk("\t first_valid_page=%08x\n", mle_hdr->first_valid_page);
    printk("\t mle_start_off=%x\n", mle_hdr->mle_start_off);
    printk("\t mle_end_off=%x\n", mle_hdr->mle_end_off);
}

/*
 * build_mle_pagetable()
 */

/* page dir/table entry is phys addr + P + R/W + PWT */
#define MAKE_PDTE(addr)  (((uint64_t)(unsigned long)(addr) & PAGE_MASK) | 0x01)

/* we assume/know that our image is <2MB and thus fits w/in a single */
/* PT (512*4KB = 2MB) and thus fixed to 1 pg dir ptr and 1 pgdir and */
/* 1 ptable = 3 pages and just 1 loop loop for ptable MLE page table */
/* can only contain 4k pages */

static void *build_mle_pagetable(uint32_t mle_start, uint32_t mle_size)
{
    void *ptab_base;
    uint32_t ptab_size, mle_off;
    void *pg_dir_ptr_tab, *pg_dir, *pg_tab;
    uint64_t *pte;

    printk("MLE start=%x, end=%x, size=%x\n", mle_start, mle_start+mle_size,
           mle_size);
    if ( mle_size > 512*PAGE_SIZE ) {
        printk("MLE size too big for single page table\n");
        return NULL;
    }


    /* should start on page boundary */
    if ( mle_start & ~PAGE_MASK ) {
        printk("MLE start is not page-aligned\n");
        return NULL;
    }

    /* place ptab_base below MLE */
    ptab_size = 3 * PAGE_SIZE;      /* pgdir ptr + pgdir + ptab = 3 */
    ptab_base = (void *)((mle_start - ptab_size) & PAGE_MASK);
    memset(ptab_base, 0, ptab_size);
    printk("ptab_size=%x, ptab_base=%p\n", ptab_size, ptab_base);

    pg_dir_ptr_tab = ptab_base;
    pg_dir         = pg_dir_ptr_tab + PAGE_SIZE;
    pg_tab         = pg_dir + PAGE_SIZE;

    /* only use first entry in page dir ptr table */
    *(uint64_t *)pg_dir_ptr_tab = MAKE_PDTE(pg_dir);

    /* only use first entry in page dir */
    *(uint64_t *)pg_dir = MAKE_PDTE(pg_tab);

    pte = pg_tab;
    mle_off = 0;
    do {
        *pte = MAKE_PDTE(mle_start + mle_off);

        pte++;
        mle_off += PAGE_SIZE;
    } while ( mle_off < mle_size );

    return ptab_base;
}

/* size can be NULL */
static bool find_sinit(multiboot_info_t *mbi, void **base, uint32_t *size)
{
    module_t *mods;
    uint32_t size2 = 0;
    void *base2 = NULL;
    int i;

    if ( base == NULL ) {
        printk("find_sinit() base is NULL\n");
        return false;
    }
    *base = NULL;
    if ( size != NULL )
        *size = 0;

    if ( mbi->mods_addr == 0 || mbi->mods_count == 0 ) {
        printk("no module info\n");
        return false;
    }

    mods = (module_t *)(mbi->mods_addr);
    for ( i = mbi->mods_count - 1; i > 0; i-- ) {
        base2 = (void *)mods[i].mod_start;
        size2 = mods[i].mod_end - (unsigned long)(base2);
        /* check if this is really an SINIT AC module */
        if ( is_sinit_acmod(base2, size2) )
            break;
    }
    /* not found */
    if ( i == 0 ) {
        printk("no SINIT AC module found\n");
        return false;
    }
    printk("user-provided SINIT found: %s\n", (const char *)mods[i].string);

    *base = base2;
    if ( size != NULL )
        *size = size2;
    return true;
}

static bool find_lcp_manifest(multiboot_info_t *mbi, void **base,
                              uint32_t *size)
{
    size_t size2 = 0;
    void *base2 = NULL;

    if ( base == NULL ) {
        printk("find_lcp_manifest() base is NULL\n");
        return false;
    }
    *base = NULL;
    if ( size != NULL )
        *size = 0;

    find_module_by_uuid(mbi, &base2, &size2, &((uuid_t)LCP_POLICY_DATA_UUID));

    /* not found */
    if ( base2 == NULL ) {
        printk("no LCP manifest found\n");
        return false;
    }

    printk("LCP manifest found\n");

    *base = base2;
    if ( size != NULL )
        *size = size2;
    return true;
}

/*
 * sets up TXT heap
 */
static txt_heap_t *init_txt_heap(void *ptab_base, acm_hdr_t *sinit,
                                 multiboot_info_t *mbi)
{
    txt_heap_t *txt_heap;
    os_sinit_data_t *os_sinit_data;
    os_mle_data_t *os_mle_data;
    uint64_t *size;
    uint32_t os_sinit_data_ver;
    uint64_t max_ram;
    void *lcp_base = NULL;
    uint32_t lcp_size = 0;

    txt_heap = get_txt_heap();

    /*
     * BIOS to OS/loader data already setup by BIOS
     */
    if ( !verify_txt_heap(txt_heap, true) )
        return NULL;

    /*
     * OS/loader to MLE data
     */
    os_mle_data = get_os_mle_data_start(txt_heap);
    size = (uint64_t *)((uint32_t)os_mle_data - sizeof(uint64_t));
    *size = sizeof(*os_mle_data) + sizeof(uint64_t);
    memset(os_mle_data, 0, sizeof(*os_mle_data));
    os_mle_data->version = 0x01;
    os_mle_data->mbi = mbi;
    rdmsrl(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

    /*
     * OS/loader to SINIT data
     */
    os_sinit_data_ver = get_supported_os_sinit_data_ver(sinit);
    printk("SINIT supports os_sinit_data version %x\n",
           os_sinit_data_ver);
    /* warn if SINIT supports more recent OS to SINIT data version than us */
    if ( os_sinit_data_ver > 0x03 )
        printk("SINIT's os_sinit_data version unsupported (%x)\n",
               os_sinit_data_ver);
    os_sinit_data = get_os_sinit_data_start(txt_heap);
    size = (uint64_t *)((uint32_t)os_sinit_data - sizeof(uint64_t));
    *size = sizeof(*os_sinit_data) + sizeof(uint64_t);
    memset(os_sinit_data, 0, sizeof(*os_sinit_data));
    /* common to all versions */
    /* this is phys addr */
    os_sinit_data->mle_ptab = (uint64_t)(unsigned long)ptab_base;
    os_sinit_data->mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;
    /* this is linear addr (offset from MLE base) of mle header */
    os_sinit_data->mle_hdr_base = (uint64_t)&g_mle_hdr - (uint64_t)&_mle_start;
    /* SINIT supports more recent version than we do, so use our most recent */
    if ( os_sinit_data_ver >= 0x03 ) {
        os_sinit_data->version = 0x03;     /* 0x03 is the max we support */

        max_ram = get_max_ram(mbi);
        if ( max_ram == 0 ) {
            printk("max_ram is 0\n");
            return NULL;
        }

        set_vtd_pmrs(os_sinit_data, max_ram);

        find_lcp_manifest(mbi, &lcp_base, &lcp_size);
        os_sinit_data->v3.lcp_po_base = (unsigned long)lcp_base;
        os_sinit_data->v3.lcp_po_size = lcp_size;

        /* if we found a manifest, remove it from module list so that */
        /* VMM/kernel doesn't see an extra file */
        if ( lcp_base != NULL ) {
            if ( remove_module(mbi, lcp_base) == NULL ) {
                printk("failed to remove LCP manifest from module list\n");
                return NULL;
            }
        }
    }
    else
        os_sinit_data->version = 0x01;
    print_os_sinit_data(os_sinit_data);

    /*
     * SINIT to MLE data will be setup by SINIT
     */

    return txt_heap;
}

void txt_wakeup_cpus(void)
{
    struct {
        uint16_t  limit;
        uint32_t  base;
    } gdt;
    uint16_t cs;
    mle_join_t mle_join;
    int ap_wakeup_count;

    atomic_set(&ap_wfs_count, 0);

    /* RLPs will use our GDT and CS */
    __asm__ __volatile__ ("sgdt (%0) \n" :: "a"(&gdt) : "memory");
    __asm__ __volatile__ ("mov %%cs, %0\n" : "=r"(cs));

    mle_join.entry_point = (uint32_t)(unsigned long)&_txt_wakeup;
    mle_join.seg_sel = cs;
    mle_join.gdt_base = gdt.base;
    mle_join.gdt_limit = gdt.limit;

    printk("mle_join.entry_point = %x\n", mle_join.entry_point);
    printk("mle_join.seg_sel = %x\n", mle_join.seg_sel);
    printk("mle_join.gdt_base = %x\n", mle_join.gdt_base);
    printk("mle_join.gdt_limit = %x\n", mle_join.gdt_limit);

    write_priv_config_reg(TXTCR_MLE_JOIN, (uint64_t)(unsigned long)&mle_join);

    printk("joining RLPs to MLE with GETSEC[WAKEUP]\n");
    __getsec_wakeup();

    printk("GETSEC[WAKEUP] completed\n");

    /* assume BIOS isn't lying to us about # CPUs, else some CPUS may not */
    /* have entered wait-for-sipi before we launch xen *or* we have to wait */
    /* for timeout before launching xen */
    /* if BIOS doesn't tell us, assume 1 (all TXT-capable CPUs have at */
    /* least 2 cores) */
    txt_heap_t *txt_heap = get_txt_heap();
    bios_os_data_t *bios_os_data = get_bios_os_data_start(txt_heap);
    if ( bios_os_data->version >= 0x02 )
        ap_wakeup_count = bios_os_data->v2.num_logical_procs - 1;
    else
        ap_wakeup_count = 1;

    printk("waiting for all APs (%d) to enter wait-for-sipi...\n",
           ap_wakeup_count);
    /* wait for all APs that woke up to have entered wait-for-sipi */
    uint32_t timeout = AP_WFS_TIMEOUT;
    do {
        cpu_relax();
        timeout--;
    } while ( (atomic_read(&ap_wfs_count) < ap_wakeup_count) && timeout > 0 );
    printk("all APs in wait-for-sipi\n");

    /* enable SMIs (do this after APs have been awakened and sync'ed w/ BSP) */
    printk("enabling SMIs on BSP\n");
    __getsec_smctrl();
}

bool txt_is_launched(void)
{
    txt_sts_t sts;

    sts._raw = read_pub_config_reg(TXTCR_STS);

    return sts.senter_done_sts;
}

tb_error_t txt_launch_environment(multiboot_info_t *mbi)
{
    acm_hdr_t *sinit = NULL;
    void *mle_ptab_base;
    os_mle_data_t *os_mle_data;
    txt_heap_t *txt_heap;

    /*
     * find SINIT AC module in modules list (it should be one of last three)
     */
    if ( find_sinit(mbi, (void **)&sinit, NULL) ) {
        /* check if it matches chipset */
        if ( !does_acmod_match_chipset(sinit) ) {
            printk("SINIT does not match chipset\n");
            sinit = NULL;
        }
        /* remove it from module list so that VMM/kernel doesn't see an */
        /* extra file */
        if ( remove_module(mbi, sinit) == NULL ) {
            printk("failed to remove SINIT module from module list\n");
            return TB_ERR_FATAL;
        }
    }

    /* if it is newer than BIOS-provided version, then copy it to */
    /* BIOS reserved region */
    sinit = copy_sinit(sinit);
    if ( sinit == NULL )
        return TB_ERR_SINIT_NOT_PRESENT;
    /* do some checks on it */
    if ( !verify_acmod(sinit) )
        return TB_ERR_ACMOD_VERIFY_FAILED;

    /* print some debug info */
    print_file_info();
    print_mle_hdr(&g_mle_hdr);

    /* create MLE page table */
    mle_ptab_base = build_mle_pagetable(
                             g_mle_hdr.mle_start_off + TBOOT_BASE_ADDR,
                             g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off);
    if ( mle_ptab_base == NULL )
        return TB_ERR_FATAL;

    /* initialize TXT heap */
    txt_heap = init_txt_heap(mle_ptab_base, sinit, mbi);
    if ( txt_heap == NULL )
        return TB_ERR_FATAL;

    /* save MTRRs before we alter them for SINIT launch */
    os_mle_data = get_os_mle_data_start(txt_heap);
    save_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* set MTRRs properly for AC module (SINIT) */
    set_mtrrs_for_acmod(sinit);

    printk("executing GETSEC[SENTER]...\n");
    __getsec_senter((uint32_t)sinit, (sinit->size)*4);
    printk("ERROR--we should not get here!\n");
    return TB_ERR_FATAL;
}

bool txt_prepare_platform(void)
{
    if ( is_tpm_ready(0) )
        return true;
    else
        return false;
}

bool txt_prepare_cpu(void)
{
    unsigned long eflags, cr0;
    uint64_t mcg_cap, mcg_stat;

    /* must be running at CPL 0 => this is implicit in even getting this far */
    /* since our bootstrap code loads a GDT, etc. */

    cr0 = read_cr0();

    /* must be in protected mode */
    if ( !(cr0 & X86_CR0_PE) ) {
        printk("ERR: not in protected mode\n");
        return false;
    }

    /* cache must be enabled (CR0.CD = CR0.NW = 0) */
    if ( cr0 & X86_CR0_CD ) {
        printk("CR0.CD set\n");
        cr0 &= ~X86_CR0_CD;
    }
    if ( cr0 & X86_CR0_NW ) {
        printk("CR0.NW set\n");
        cr0 &= ~X86_CR0_NW;
    }

    /* native FPU error reporting must be enabled for proper */
    /* interaction behavior */
    if ( !(cr0 & X86_CR0_NE) ) {
        printk("CR0.NE not set\n");
        cr0 |= X86_CR0_NE;
    }

    write_cr0(cr0);

    /* cannot be in virtual-8086 mode (EFLAGS.VM=1) */
    __save_flags(eflags);
    if ( eflags & X86_EFLAGS_VM ) {
        printk("EFLAGS.VM set\n");
        __restore_flags(eflags | ~X86_EFLAGS_VM);
    }

    printk("CR0 and EFLAGS OK\n");

    /*
     * verify that we're not already in a protected environment
     */
    if ( txt_is_launched() ) {
        printk("already in protected environment\n");
        return false;
    }

    /*
     * verify all machine check status registers are clear
     */

    /* no machine check in progress (IA32_MCG_STATUS.MCIP=1) */
    rdmsrl(MSR_IA32_MCG_STATUS, mcg_stat);
    if ( mcg_stat & 0x04 ) {
        printk("machine check in progress\n");
        return false;
    }

    /* all machine check regs are clear */
    rdmsrl(MSR_IA32_MCG_CAP, mcg_cap);
    for ( int i = 0; i < (mcg_cap & 0xff); i++ ) {
        rdmsrl(MSR_IA32_MC0_STATUS + 4*i, mcg_stat);
        if ( mcg_stat & (1ULL << 63) ) {
            printk("MCG[%d] = %Lx ERROR\n", i, mcg_stat);
            return false;
        }
    }

    printk("no machine check errors\n");

    /* all is well with the processor state */
    printk("CPU is ready for SENTER\n");

    return true;
}

tb_error_t txt_post_launch(void)
{
    txt_heap_t *txt_heap;
    os_mle_data_t *os_mle_data;
    tb_error_t err;

    /* verify MTRRs, VT-d settings, TXT heap, etc. */
    err = txt_post_launch_verify_platform();
    if ( err != TB_ERR_NONE ) {
        printk("failed to verify platform\n");
        return err;
    }

    /* clear error config registers so that we start fresh */
    write_priv_config_reg(TXTCR_ERRORCODE, 0x00000000);
    write_priv_config_reg(TXTCR_ESTS, 0xffffffff);  /* write 1's to clear */

    /* always set the LT.CMD.SECRETS flag */
    write_priv_config_reg(TXTCR_CMD_SECRETS, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
    printk("set LT.CMD.SECRETS flag\n");

    /* get saved OS state (os_mvmm_data_t) from LT heap */
    txt_heap = get_txt_heap();
    os_mle_data = get_os_mle_data_start(txt_heap);

    /* restore pre-SENTER MTRRs that were overwritten for SINIT launch */
    restore_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* restore pre-SENTER IA32_MISC_ENABLE_MSR (no verification needed) */
    wrmsrl(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

    /* open TPM locality 1 */
    write_priv_config_reg(TXTCR_CMD_OPEN_LOCALITY1, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
    printk("opened TPM locality 1\n");

    return TB_ERR_NONE;
}

void txt_cpu_wakeup(uint32_t cpuid)
{
    txt_heap_t *txt_heap;
    os_mle_data_t *os_mle_data;

    printk("cpu %x waking up from TXT sleep\n", cpuid);

    txt_heap = get_txt_heap();
    os_mle_data = get_os_mle_data_start(txt_heap);

    /* apply (validated) (pre-SENTER) MTRRs from BSP to each AP */
    restore_mtrrs(&(os_mle_data->saved_mtrr_state));

    /* restore pre-SENTER IA32_MISC_ENABLE_MSR */
    wrmsrl(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

    /* enable SMIs */
    printk("enabling SMIs on cpu %x\n", cpuid);
    __getsec_smctrl();

    handle_init_sipi_sipi(cpuid);
}

tb_error_t txt_protect_mem_regions(void)
{
    uint64_t base, size;
    txt_heap_t* txt_heap;
    sinit_mle_data_t *sinit_mle_data;
    sinit_mdr_t *mdrs_base;
    uint32_t num_mdrs;

    /*
     * TXT has 2 regions of RAM that need to be reserved for use by only the
     * hypervisor; not even dom0 should have access:
     *   TXT heap, SINIT AC module
     */

    /* TXT heap */
    base = read_pub_config_reg(TXTCR_HEAP_BASE);
    size = read_pub_config_reg(TXTCR_HEAP_SIZE);
    printk("protecting TXT heap (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, E820_UNUSABLE) )
        return TB_ERR_FATAL;

    /* SINIT */
    base = read_pub_config_reg(TXTCR_SINIT_BASE);
    size = read_pub_config_reg(TXTCR_SINIT_SIZE);
    printk("protecting SINIT (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, E820_UNUSABLE) )
        return TB_ERR_FATAL;

    /* ensure that memory not marked as good RAM by the MDRs is RESERVED in
       the e820 table */
    txt_heap = get_txt_heap();
    sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    if ( sinit_mle_data->version <= 0x01 ) {
        num_mdrs = sinit_mle_data->v1.num_mdrs;
        mdrs_base = sinit_mle_data->v1.mdrs;
    }
    else {
        num_mdrs = sinit_mle_data->v5.num_mdrs;
        mdrs_base = (sinit_mdr_t *)(((void *)sinit_mle_data -
                                     sizeof(uint64_t)) +
                                    sinit_mle_data->v5.mdrs_off);
    }
    printk("verifying e820 table against SINIT MDRs: ");
    if ( !verify_e820_map(mdrs_base, num_mdrs) ) {
        printk("verification failed.\n");
        return TB_ERR_POST_LAUNCH_VERIFICATION;
    }
    printk("verification succeeded.\n");

#if 0
    /*
     * some BIOSes mark the TPM and LT public space as reserved
     * this will cause xen to give these regions to dom_io instead of dom0
     * however, if we mark them as protected, then they won't be given
     * to dom_io and dom0 will be allowed to map them as MMIO (not as RAM)
     * this should have no effect on system's whose BIOS doesn't do this
     */

    /* TPM localities */
    base = TPM_LOCALITY_BASE;
    size = NR_TPM_LOCALITY_PAGES * PAGE_SIZE;
    printk("protecting TPM localities (%Lx - %Lx) in e820 table\n",
           base, (base + size - 1));
    if ( !e820_protect_region(base, size, E820_PROTECTED) )
        return false;

    /* TXT public space */
    base = TXT_PUB_CONFIG_REGS_BASE;
    size = NR_TXT_CONFIG_PAGES * PAGE_SIZE;
    printk("protecting TXT Public Space (%Lx - %Lx) in e820 table\n",
           base, (base + size - 1));
    if ( !e820_protect_region(base, size, E820_PROTECTED) )
        return false;
#endif

    /* TXT private space */
    base = TXT_PRIV_CONFIG_REGS_BASE;
    size = NR_TXT_CONFIG_PAGES * PAGE_SIZE;
    printk("protecting TXT Private Space (%Lx - %Lx) in e820 table\n",
           base, (base + size - 1));
    if ( !e820_protect_region(base, size, E820_UNUSABLE) )
        return TB_ERR_FATAL;

    return TB_ERR_NONE;
}

void txt_shutdown(void)
{
    unsigned long apicbase;

    rdmsrl(MSR_IA32_APICBASE, apicbase);
    if ( !(apicbase & MSR_IA32_APICBASE_BSP) ) {
        printk("calling txt_shutdown on AP\n");
        while ( true )
            __asm__ __volatile__("sti; hlt": : :"memory");
    }

    /* set LT.CMD.NO-SECRETS flag (i.e. clear SECRETS flag) */
    write_priv_config_reg(TXTCR_CMD_NO_SECRETS, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    printk("secrets flag cleared\n");

    /* close TXT private config space */
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    write_priv_config_reg(TXTCR_CMD_CLOSE_PRIVATE, 0x01);
    read_pub_config_reg(TXTCR_E2STS);    /* fence */
    printk("private config space closed\n");

    /* SMXE may not be enabled any more, so set it to make sure */
    write_cr4(read_cr4() | X86_CR4_SMXE);

    /* call GETSEC[SEXIT] */
    printk("executing GETSEC[SEXIT]...\n");
    __getsec_sexit();
    printk("measured environment torn down\n");
}

bool txt_s3_launch_environment(void)
{
    acm_hdr_t *sinit;

    /* get sinit binary loaded */
    sinit = (acm_hdr_t *)(uint32_t)read_pub_config_reg(TXTCR_SINIT_BASE);
    if ( sinit == NULL )
        return false;

    /* set MTRRs properly for AC module (SINIT) */
    set_mtrrs_for_acmod(sinit);

    printk("executing GETSEC[SENTER]...\n");
    __getsec_senter((uint32_t)sinit, (sinit->size)*4);
    printk("ERROR--we should not get here!\n");
    return false;
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
