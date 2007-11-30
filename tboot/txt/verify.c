/*
 * verify.c: verify that platform and processor supports Intel(r) TXT
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
#include <types.h>
#include <stdbool.h>
#include <msr.h>
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <cpufeature.h>
#include <page.h>
#include <printk.h>
#include <multiboot.h>
#include <tb_error.h>
#include <e820.h>
#include <acpi.h>
#include <txt/txt.h>
#include <txt/smx.h>
#include <txt/heap.h>
#include <txt/verify.h>
#include <txt/mtrrs.h>

extern char _start[];           /* start of module */
extern char _end[];             /* end of module */

/*
 * CPUID extended feature info
 */
static unsigned int g_cpuid_ext_feat_info;

/*
 * IA32_FEATURE_CONTROL_MSR
 */
static unsigned long g_feat_ctrl_msr;


static void read_processor_info(void)
{
    unsigned long f1, f2;
    
    /* is CPUID supported? */
    /* (it's supported if ID flag in EFLAGS can be set and cleared) */
    asm("pushf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "mov %0,%1\n\t"
        "xor %2,%0\n\t"
        "push %0\n\t"
        "popf\n\t"
        "pushf\n\t"
        "pop %0\n\t"
        "popf\n\t"
        : "=&r" (f1), "=&r" (f2)
        : "ir" (X86_EFLAGS_ID));
    if ( ((f1^f2) & X86_EFLAGS_ID) == 0 ) {
        g_cpuid_ext_feat_info = 0;
        return;
    }

    g_cpuid_ext_feat_info = cpuid_ecx(1);

    rdmsrl(IA32_FEATURE_CONTROL_MSR, g_feat_ctrl_msr);
    printk("IA32_FEATURE_CONTROL_MSR: %08lx\n", g_feat_ctrl_msr);
}

static bool supports_vmx(void)
{
    /* check that processor supports VMX instructions */
    if ( !(g_cpuid_ext_feat_info & bitmaskof(X86_FEATURE_VMXE)) ) {
        printk("ERR: CPU does not support VMX\n");
        return false;
    }
    printk("CPU is VMX-capable\n");

    /* and that VMX is enabled in the feature control MSR */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX) ) {
        printk("ERR: VMXON disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

static bool supports_smx(void)
{
    /* check that processor supports SMX instructions */
    if ( !(g_cpuid_ext_feat_info & bitmaskof(X86_FEATURE_SMXE)) ) {
        printk("ERR: CPU does not support SMX\n");
        return false;
    }
    printk("CPU is SMX-capable\n");

    /*
     * and that SMX is enabled in the feature control MSR
     */

    /* check that the MSR is locked -- BIOS should always lock it */
    if ( !(g_feat_ctrl_msr & IA32_FEATURE_CONTROL_MSR_LOCK) ) {
        printk("ERR: IA32_FEATURE_CONTROL_MSR_LOCK is not locked\n");
        /* in general this should not happen, as BIOS is required to lock */
        /* the MSR; but it may be desirable to allow it sometimes */
#ifdef PERMISSIVE_BOOT
        /* we enable VMX outside of SMX as well so that if there was some */
        /* error in the TXT boot, VMX will continue to work */
        g_feat_ctrl_msr |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_IN_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_VMX_OUT_SMX |
                           IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                           IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL |
                           IA32_FEATURE_CONTROL_MSR_LOCK;
        wrmsrl(IA32_FEATURE_CONTROL_MSR, g_feat_ctrl_msr);
        return true;
#else
        return false;
#endif
    }

    /* check that SENTER (w/ full params) is enabled */
    if ( !(g_feat_ctrl_msr & (IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER |
                              IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL)) ) {
        printk("ERR: SENTER disabled by feature control MSR (%lx)\n",
               g_feat_ctrl_msr);
        return false;
    }

    return true;
}

static tb_error_t supports_txt(void)
{
    capabilities_t cap;

    /* processor must support SMX */
    if ( !supports_smx() )
        return TB_ERR_SMX_NOT_SUPPORTED;
    if ( !supports_vmx() )
        return TB_ERR_VMX_NOT_SUPPORTED;

    /* testing for chipset support requires enabling SMX on the processor */
    write_cr4(read_cr4() | X86_CR4_SMXE);
    printk("SMX is enabled\n");

    /*
     * verify that an TXT-capable chipset is present and 
     * check that all needed SMX capabilities are supported
     */

    cap = __getsec_capabilities(0);
    if ( cap.chipset_present ) {
        if ( cap.senter && cap.sexit && cap.parameters && cap.smctrl &&
             cap.wakeup ) {
            printk("TXT chipset and all needed capabilities present\n");
            return TB_ERR_NONE;
        }
        else
            printk("ERR: insufficient SMX capabilities (%x)\n", cap._raw);
    }
    else
        printk("ERR: TXT-capable chipset not present\n");

    /* since we are failing, we should clear the SMX flag */
    write_cr4(read_cr4() & ~X86_CR4_SMXE);

    return TB_ERR_TXT_NOT_SUPPORTED;
}

static void print_bios_os_data(bios_os_data_t *bios_os_data)
{
    printk("bios_os_data (@%p, %Lx):\n", bios_os_data,
           *((uint64_t *)bios_os_data - 1));
    printk("\t version=%x\n", bios_os_data->version);
    printk("\t bios_sinit_size=%x\n", bios_os_data->bios_sinit_size);
    if ( bios_os_data->version >= 0x02 ) {
        printk("\t lcp_pd_base=%Lx\n", bios_os_data->v2.lcp_pd_base);
        printk("\t lcp_pd_size=%Lx\n", bios_os_data->v2.lcp_pd_size);
        printk("\t num_logical_procs=%x\n",
               bios_os_data->v2.num_logical_procs);
    }
}

static bool verify_bios_os_data(txt_heap_t *txt_heap)
{
    uint64_t size, heap_size;
    bios_os_data_t *bios_os_data;

    /* check size */
    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
    size = get_bios_os_data_size(txt_heap);
    if ( size == 0 ) {
        printk("BIOS to OS data size is 0\n");
        return false;
    }
    if ( size > heap_size ) {
        printk("BIOS to OS data size is larger than heap size "
               "(%Lx, heap size=%Lx)\n", size, heap_size);
        return false;
    }

    bios_os_data = get_bios_os_data_start(txt_heap);

    /* check version */
    /* we assume backwards compatibility but print a warning */
    if ( bios_os_data->version > 0x02 )
        printk("unsupported BIOS to OS data version (%x)\n",
               bios_os_data->version);

    /* no field checks (bios_sinit_size field can be 0) */

    print_bios_os_data(bios_os_data);

    return true;
}

static void print_os_mle_data(os_mle_data_t *os_mle_data)
{
    printk("os_mle_data (@%p, %Lx):\n", os_mle_data,
           *((uint64_t *)os_mle_data - 1));
    printk("\t version=%x\n", os_mle_data->version);
    /* TBD: perhaps eventually print saved_mtrr_state field */
    printk("\t mbi=%p\n", os_mle_data->mbi);
}

static bool verify_os_mle_data(txt_heap_t *txt_heap)
{
    uint64_t size, heap_size;
    os_mle_data_t *os_mle_data;

    /* check size */
    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
    size = get_os_mle_data_size(txt_heap);
    if ( size == 0 ) {
        printk("OS to MLE data size is 0\n");
        return false;
    }
    if ( size > heap_size ) {
        printk("OS to MLE data size is larger than heap size "
               "(%Lx, heap size=%Lx)\n", size, heap_size);
        return false;
    }
    if ( size < sizeof(os_mle_data_t) ) {
        printk("OS to MLE data size (%Lx) is smaller than "
               "os_mle_data_t size (%x)\n", size, sizeof(os_mle_data_t));
        return false;
    }

    os_mle_data = get_os_mle_data_start(txt_heap);

    /* check version */
    /* since this data is from our pre-launch to post-launch code only, it */
    /* should always be this */
    if ( os_mle_data->version != 0x01 ) {
        printk("unsupported OS to MLE data version (%x)\n",
               os_mle_data->version);
        return false;
    }

    /* field checks */
    if ( os_mle_data->mbi == NULL ) {
        printk("OS to MLE data mbi field is NULL\n");
        return false;
    }

    print_os_mle_data(os_mle_data);

    return true;
}

void print_os_sinit_data(os_sinit_data_t *os_sinit_data)
{
    printk("os_sinit_data (@%p, %Lx):\n", os_sinit_data,
           *((uint64_t *)os_sinit_data - 1));
    printk("\t version=%x\n", os_sinit_data->version);
    printk("\t mle_ptab=%Lx\n", os_sinit_data->mle_ptab);
    printk("\t mle_size=%Lx\n", os_sinit_data->mle_size);
    printk("\t mle_hdr_base=%Lx\n", os_sinit_data->mle_hdr_base);
    if ( os_sinit_data->version >= 0x03 ) {
        printk("\t vtd_pmr_lo_base=%Lx\n", os_sinit_data->v3.vtd_pmr_lo_base);
        printk("\t vtd_pmr_lo_size=%Lx\n", os_sinit_data->v3.vtd_pmr_lo_size);
        printk("\t vtd_pmr_hi_base=%Lx\n", os_sinit_data->v3.vtd_pmr_hi_base);
        printk("\t vtd_pmr_hi_size=%Lx\n", os_sinit_data->v3.vtd_pmr_hi_size);
        printk("\t lcp_po_base=%Lx\n", os_sinit_data->v3.lcp_po_base);
        printk("\t lcp_po_size=%Lx\n", os_sinit_data->v3.lcp_po_size);
    }
}

static bool verify_os_sinit_data(txt_heap_t *txt_heap)
{
    uint64_t size, heap_size;
    os_sinit_data_t *os_sinit_data;

    /* check size */
    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
    size = get_os_sinit_data_size(txt_heap);
    if ( size == 0 ) {
        printk("OS to SINIT data size is 0\n");
        return false;
    }
    if ( size > heap_size ) {
        printk("OS to SINIT data size is larger than heap size "
               "(%Lx, heap size=%Lx)\n", size, heap_size);
        return false;
    }

    os_sinit_data = get_os_sinit_data_start(txt_heap);

    /* check version */
    if ( os_sinit_data->version > 0x03 ) {
        printk("unsupported OS to SINIT data version (%x)\n",
               os_sinit_data->version);
        return false;
    }

    /* if it is version 0x01 then none of the fields get used post-launch */
    /* so no need to verify them (SINIT will have done that) */
    if ( os_sinit_data->version > 0x01 ) {
        /* only check minimal size */
        if ( size < sizeof(os_sinit_data_t) ) {
            printk("OS to SINIT data size (%Lx) is smaller than "
                   "os_sinit_data_t (%x)\n", size, sizeof(os_sinit_data_t));
            return false;
        }
    }

    print_os_sinit_data(os_sinit_data);

    return true;
}

static void print_sinit_mdrs(sinit_mdr_t mdrs[], uint32_t num_mdrs)
{
    static char *mem_types[] = {"GOOD", "SMRAM OVERLAY", "SMRAM NON-OVERLAY",
                                "PCIE EXTENDED CONFIG", "PROTECTED"};

    printk("\t sinit_mdrs:\n");
    for ( int i = 0; i < num_mdrs; i++ ) {
        printk("\t\t %016Lx - %016Lx ", mdrs[i].base,
               mdrs[i].base + mdrs[i].length);
        if ( mdrs[i].mem_type < sizeof(mem_types)/sizeof(mem_types[0]) )
            printk("(%s)\n", mem_types[mdrs[i].mem_type]);
        else
            printk("(%d)\n", (int)mdrs[i].mem_type);
    }
}

static void print_hash(sha1_hash_t hash)
{
    for ( int i = 0; i < SHA1_SIZE; i++ )
        printk("%02x ", hash[i]);
    printk("\n");
}

static void print_sinit_mle_data(sinit_mle_data_t *sinit_mle_data)
{
    printk("sinit_mle_data (@%p, %Lx):\n", sinit_mle_data,
           *((uint64_t *)sinit_mle_data - 1));
    printk("\t version=%x\n", sinit_mle_data->version);
    if ( sinit_mle_data->version == 0x01 )
        print_sinit_mdrs(sinit_mle_data->v1.mdrs, sinit_mle_data->v1.num_mdrs);
    else if ( sinit_mle_data->version >= 0x05 ) {
        printk("\t bios_acm_id=\n\t");
        print_hash(sinit_mle_data->v5.bios_acm_id);
        printk("\t edx_senter_flags=%x\n",
               sinit_mle_data->v5.edx_senter_flags);
        printk("\t mseg_valid=%Lx\n", sinit_mle_data->v5.mseg_valid);
        printk("\t sinit_hash=\n\t");
               print_hash(sinit_mle_data->v5.sinit_hash);
        printk("\t mle_hash=\n\t");
        print_hash(sinit_mle_data->v5.mle_hash);
        printk("\t stm_hash=\n\t");
               print_hash(sinit_mle_data->v5.stm_hash);
        printk("\t lcp_policy_hash=\n\t");
               print_hash(sinit_mle_data->v5.lcp_policy_hash);
        printk("\t lcp_policy_control=%x\n",
               sinit_mle_data->v5.lcp_policy_control);
        printk("\t num_mdrs=%x\n", sinit_mle_data->v5.num_mdrs);
        printk("\t mdrs_off=%x\n", sinit_mle_data->v5.mdrs_off);
        printk("\t num_vtd_dmars=%x\n", sinit_mle_data->v5.num_vtd_dmars);
        printk("\t vtd_dmars_off=%x\n", sinit_mle_data->v5.vtd_dmars_off);
        print_sinit_mdrs((sinit_mdr_t *)(((void *)sinit_mle_data - sizeof(uint64_t)) + sinit_mle_data->v5.mdrs_off), sinit_mle_data->v5.num_mdrs);
    }
}

static bool verify_sinit_mle_data(txt_heap_t *txt_heap)
{
    uint64_t size, heap_size;
    sinit_mle_data_t *sinit_mle_data;

    /* check size */
    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
    size = get_sinit_mle_data_size(txt_heap);
    if ( size == 0 ) {
        printk("SINIT to MLE data size is 0\n");
        return false;
    }
    if ( size > heap_size ) {
        printk("SINIT to MLE data size is larger than heap size\n"
               "(%Lx, heap size=%Lx)\n", size, heap_size);
        /* TBD: un-comment this when have fixed SINIT
           return false; */
    }

    sinit_mle_data = get_sinit_mle_data_start(txt_heap);

    /* check version */
    sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    if ( sinit_mle_data->version > 0x05 ) {
        printk("unsupported SINIT to MLE data version (%x)\n",
               sinit_mle_data->version);
        return false;
    }

    /* this data is generated by SINIT and so is implicitly trustworthy, */
    /* so we don't need to validate it's fields */

    print_sinit_mle_data(sinit_mle_data);

    return true;
}

static bool verify_vtd_pmrs(txt_heap_t *txt_heap)
{
    uint64_t max_ram;
    os_sinit_data_t *os_sinit_data, tmp_os_sinit_data;
    os_mle_data_t *os_mle_data;

    os_sinit_data = get_os_sinit_data_start(txt_heap);

    if ( os_sinit_data->version > 0x01 ) {
        /* make sure the VT-d PMRs were actually set to cover what */
        /* we expect */
        /* calculate what they should have been */
        os_mle_data = get_os_mle_data_start(txt_heap);
        max_ram = get_max_ram(os_mle_data->mbi);
        if ( max_ram == 0 ) {
            printk("max_ram is 0\n");
            return false;
        }
        memset(&tmp_os_sinit_data, 0, sizeof(tmp_os_sinit_data));
        tmp_os_sinit_data.version = os_sinit_data->version;
        set_vtd_pmrs(&tmp_os_sinit_data, max_ram);
        /* compare to current values */
        if ( (tmp_os_sinit_data.v3.vtd_pmr_lo_base !=
              os_sinit_data->v3.vtd_pmr_lo_base) ||
             (tmp_os_sinit_data.v3.vtd_pmr_lo_size !=
              os_sinit_data->v3.vtd_pmr_lo_size) ||
             (tmp_os_sinit_data.v3.vtd_pmr_hi_base !=
              os_sinit_data->v3.vtd_pmr_hi_base) ||
             (tmp_os_sinit_data.v3.vtd_pmr_hi_size !=
              os_sinit_data->v3.vtd_pmr_hi_size) ) {
            printk("OS to SINIT data VT-d PMR settings do not match:\n");
            print_os_sinit_data(&tmp_os_sinit_data);
            print_os_sinit_data(os_sinit_data);
            return false;
        }
    }

    return true;
}

static bool verify_vtd_dmar(txt_heap_t *txt_heap)
{
    /* get the copy in heap */
    uint32_t heap_dmar = 0;
    uint32_t dmar_size = 0;
    uint32_t acpi_dmar;
    sinit_mle_data_t *sinit_mle_data;
    
    sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    printk("begin verifying vtd_dmar ...\n");
    if ( sinit_mle_data->version >= 0x05 ) {
        heap_dmar = (uint32_t)sinit_mle_data - sizeof(uint64_t) + 
                    sinit_mle_data->v5.vtd_dmars_off;
        dmar_size = sinit_mle_data->v5.num_vtd_dmars;
        printk("version = 0x05, heap_dmar = %08x, dmar_size = %08x\n",
               heap_dmar, dmar_size);
    }
    else {
        printk("version = %d, no dmar info.\n", sinit_mle_data->version);
        return true;
    }

    /* get acpi vt-d DMAR table */
    acpi_dmar = get_acpi_dmar_table();
    printk("acpi_dmar = %08x\n", acpi_dmar);
    
    if ( heap_dmar == 0 || acpi_dmar == 0 || dmar_size == 0 ) {
        printk("failed to verify VT-d DMAR table:\n"
               "\theap_dmar = %08x, acpi_dmar = %08x, dmar_size = %08x\n",
               heap_dmar, acpi_dmar, dmar_size);
        return false;
    }
    if ( memcmp((void *)heap_dmar, (void*)acpi_dmar, dmar_size) != 0 ) {
        printk("failed to verify VT-d DMAR table: not equal\n");
        return false;
    }

    printk("VT-d DMAR table OK\n");
    return true;
}

void set_vtd_pmrs(os_sinit_data_t *os_sinit_data, uint64_t max_ram)
{
    /* this is phys addr */
    /*
     * base must be 2M-aligned and size must be multiple of 2M
     * we want to protect all of mem so that any kernel allocations before
     * VT-d remapping is enabled are protected
     * TBD: we should have a cmdline option to disable this for kernels
     *      that aren't VT-d -aware
     */
    printk("max_ram=%Lx\n", max_ram);
#ifdef VT_D
    os_sinit_data->v3.vtd_pmr_lo_base = 0;
    /* since this code DMA protects all of RAM, it will only work if */
    /* xen enables VT-d translation for dom0, so don't use it if */
    /* xen's VT-d is not enabled */
    if ( max_ram & 0xffffffff00000000UL )       /* > 4GB */
        os_sinit_data->v3.vtd_pmr_lo_size = 0x100000000UL;
    else {
        /* round up since physical mem will always be a multiple of 2M */
        /* so if max_ram is not a multiple it is because there is */
        /* reserved memory above it */
        os_sinit_data->v3.vtd_pmr_lo_size =
            (max_ram + 0x200000UL - 1UL) & ~0x1fffffUL;
    }
    if ( max_ram & 0xffffffff00000000UL ) {     /* > 4GB */
        os_sinit_data->v3.vtd_pmr_hi_base = 0x100000000UL;
        os_sinit_data->v3.vtd_pmr_hi_size =
            (max_ram - 0x100000000UL) & ~0x1fffffUL;
    }
#else
    /* else just protect the MLE (i.e. tboot) */
    os_sinit_data->v3.vtd_pmr_lo_base =
        ((uint32_t)&_start - 3*PAGE_SIZE) & ~0x1fffff;
    os_sinit_data->v3.vtd_pmr_lo_size =
        ((((uint32_t)&_end - os_sinit_data->v3.vtd_pmr_lo_base)
          + 0x200000 - 1) & ~0x1fffff);
#endif   /* VT_D */
}

bool verify_txt_heap(txt_heap_t *txt_heap, bool bios_os_data_only)
{
    uint64_t size1, size2, size3, size4;

    /* verify BIOS to OS data */
    if ( !verify_bios_os_data(txt_heap) )
        return false;

    if ( bios_os_data_only )
        return true;

    /* check that total size is within the heap */
    size1 = get_bios_os_data_size(txt_heap);
    size2 = get_os_mle_data_size(txt_heap);
    size3 = get_os_sinit_data_size(txt_heap);
    size4 = get_sinit_mle_data_size(txt_heap);
    if ( (size1 + size2 + size3 + size4) >
         read_priv_config_reg(TXTCR_HEAP_SIZE) ) {
        printk("TXT heap data sizes (%Lx, %Lx, %Lx, %Lx) are larger than\n"
               "heap total size (%Lx)\n", size1, size2, size3, size4,
               read_priv_config_reg(TXTCR_HEAP_SIZE));
        /* TBD:  un-comment this when have fixed SINIT
           return false; */
    }

    /* verify OS to MLE data */
    if ( !verify_os_mle_data(txt_heap) )
        return false;

    /* verify OS to SINIT data */
    if ( !verify_os_sinit_data(txt_heap) )
        return false;

    /* verify SINIT to MLE data */
    if ( !verify_sinit_mle_data(txt_heap) )
        return false;

    return true;
}

tb_error_t txt_verify_platform(void)
{
    txt_heap_t *txt_heap;
    tb_error_t err;

    read_processor_info();

    /* support Intel(r) TXT (this includes TPM support) */
    err = supports_txt();
    if ( err != TB_ERR_NONE )
        return err;

    /* verify BIOS to OS data */
    txt_heap = get_txt_heap();
    if ( !verify_bios_os_data(txt_heap) )
        return TB_ERR_FATAL;

    return TB_ERR_NONE;
}

static bool verify_saved_mtrrs(txt_heap_t *txt_heap)
{
    os_mle_data_t *os_mle_data;
    os_mle_data = get_os_mle_data_start(txt_heap);

    return validate_mtrrs(&(os_mle_data->saved_mtrr_state));
}

tb_error_t txt_post_launch_verify_platform(void)
{
    txt_heap_t *txt_heap;

    /*
     * verify some of the heap structures
     */
    txt_heap = get_txt_heap();

    if ( !verify_txt_heap(txt_heap, false) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    /* verify the saved MTRRs */
    if ( !verify_saved_mtrrs(txt_heap) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;
            
    /* verify that VT-d PMRs were really set to protect all of RAM */
    if ( !verify_vtd_pmrs(txt_heap) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    /* verify the VT-d DMAR tables */
    if ( !verify_vtd_dmar(txt_heap) )
        return TB_ERR_POST_LAUNCH_VERIFICATION;

    return TB_ERR_NONE;
}

bool verify_e820_map(sinit_mdr_t* mdrs_base, uint32_t num_mdrs)
{
    sinit_mdr_t* mdr_entry;
    sinit_mdr_t tmp_entry;
    uint64_t base, length;
    uint32_t i, j, pos;

    if ( (mdrs_base == NULL) || (num_mdrs == 0) )
        return false;

    /* sort mdrs */
    for( i = 0; i < num_mdrs; i++ ) {
        memcpy(&tmp_entry, &mdrs_base[i], sizeof(sinit_mdr_t));
        pos = i;
        for ( j = i + 1; j < num_mdrs; j++ ) {
            if ( ( tmp_entry.base > mdrs_base[j].base )
                 || (( tmp_entry.base == mdrs_base[j].base ) &&
                     ( tmp_entry.length > mdrs_base[j].length )) ) {
                memcpy(&tmp_entry, &mdrs_base[j], sizeof(sinit_mdr_t));
                pos = j;
            }
        }
        if ( pos > i ) {
            memcpy(&mdrs_base[pos], &mdrs_base[i], sizeof(sinit_mdr_t));
            memcpy(&mdrs_base[i], &tmp_entry, sizeof(sinit_mdr_t));
        }
    }

    /* verify e820 map against mdrs */
    /* find all ranges *not* in MDRs:
       if any of it is in e820 as RAM then set that to RESERVED. */
    i = 0;
    base = 0;
    while ( i < num_mdrs ) {
        mdr_entry = &mdrs_base[i];
        i++;
        if ( mdr_entry->mem_type > MDR_MEMTYPE_GOOD )
            continue;
        length = mdr_entry->base - base;
        if ( (length > 0) && (!e820_reserve_ram(base, length)) )
            return false;
        base = mdr_entry->base + mdr_entry->length;
    }

    /* deal with the last gap */
    length = (uint64_t)-1 - base;
    return e820_reserve_ram(base, length);
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
