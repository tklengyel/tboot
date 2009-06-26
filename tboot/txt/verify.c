/*
 * verify.c: verify that platform and processor supports Intel(r) TXT
 *
 * Copyright (c) 2003-2008, Intel Corporation
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
#include <misc.h>
#include <processor.h>
#include <cpufeature.h>
#include <page.h>
#include <printk.h>
#include <multiboot.h>
#include <tb_error.h>
#include <e820.h>
#include <tboot.h>
#include <acpi.h>
#include <mle.h>
#include <hash.h>
#include <integrity.h>
#include <txt/txt.h>
#include <txt/smx.h>
#include <txt/mtrrs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/verify.h>

extern long s3_flag;

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
        /* this should not happen, as BIOS is required to lock the MSR */
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

tb_error_t supports_txt(void)
{
    capabilities_t cap;

    read_processor_info();

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

static bool verify_vtd_pmrs(txt_heap_t *txt_heap)
{
    os_sinit_data_t *os_sinit_data, tmp_os_sinit_data;
    uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;

    os_sinit_data = get_os_sinit_data_start(txt_heap);

    /*
     * make sure the VT-d PMRs were actually set to cover what
     * we expect
     */

    /* calculate what they should have been */
    /* no e820 table on S3 resume, so use saved (sealed) values */
    if ( s3_flag ) {
        min_lo_ram = g_pre_k_s3_state.vtd_pmr_lo_base;
        max_lo_ram = min_lo_ram + g_pre_k_s3_state.vtd_pmr_lo_size;
        min_hi_ram = g_pre_k_s3_state.vtd_pmr_hi_base;
        max_hi_ram = min_hi_ram + g_pre_k_s3_state.vtd_pmr_hi_size;
    }
    else {
        os_mle_data_t *os_mle_data = get_os_mle_data_start(txt_heap);
        if ( !get_ram_ranges(os_mle_data->mbi, &min_lo_ram, &max_lo_ram,
                             &min_hi_ram, &max_hi_ram) )
            return false;
    }

    /* compare to current values */
    memset(&tmp_os_sinit_data, 0, sizeof(tmp_os_sinit_data));
    tmp_os_sinit_data.version = os_sinit_data->version;
    set_vtd_pmrs(&tmp_os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram,
                 max_hi_ram);
    if ( (tmp_os_sinit_data.vtd_pmr_lo_base !=
          os_sinit_data->vtd_pmr_lo_base) ||
         (tmp_os_sinit_data.vtd_pmr_lo_size !=
          os_sinit_data->vtd_pmr_lo_size) ||
         (tmp_os_sinit_data.vtd_pmr_hi_base !=
          os_sinit_data->vtd_pmr_hi_base) ||
         (tmp_os_sinit_data.vtd_pmr_hi_size !=
          os_sinit_data->vtd_pmr_hi_size) ) {
        printk("OS to SINIT data VT-d PMR settings do not match:\n");
        print_os_sinit_data(&tmp_os_sinit_data);
        print_os_sinit_data(os_sinit_data);
        return false;
    }

    if ( !s3_flag ) {
        /* save the verified values so that they can be sealed for S3 */
        g_pre_k_s3_state.vtd_pmr_lo_base = os_sinit_data->vtd_pmr_lo_base;
        g_pre_k_s3_state.vtd_pmr_lo_size = os_sinit_data->vtd_pmr_lo_size;
        g_pre_k_s3_state.vtd_pmr_hi_base = os_sinit_data->vtd_pmr_hi_base;
        g_pre_k_s3_state.vtd_pmr_hi_size = os_sinit_data->vtd_pmr_hi_size;
    }

    return true;
}

void set_vtd_pmrs(os_sinit_data_t *os_sinit_data,
                  uint64_t min_lo_ram, uint64_t max_lo_ram,
                  uint64_t min_hi_ram, uint64_t max_hi_ram)
{
    printk("min_lo_ram: 0x%Lx, max_lo_ram: 0x%Lx\n", min_lo_ram, max_lo_ram);
    printk("min_hi_ram: 0x%Lx, max_hi_ram: 0x%Lx\n", min_hi_ram, max_hi_ram);

    /*
     * base must be 2M-aligned and size must be multiple of 2M
     * (so round bases and sizes down--rounding size up might conflict
     *  with a BIOS-reserved region and cause problems; in practice, rounding
     *  base down doesn't)
     * we want to protect all of usable mem so that any kernel allocations
     * before VT-d remapping is enabled are protected
     */

    min_lo_ram &= ~0x1fffffULL;
    uint64_t lo_size = (max_lo_ram - min_lo_ram) & ~0x1fffffULL;
    os_sinit_data->vtd_pmr_lo_base = min_lo_ram;
    os_sinit_data->vtd_pmr_lo_size = lo_size;

    min_hi_ram &= ~0x1fffffULL;
    uint64_t hi_size = (max_hi_ram - min_hi_ram) & ~0x1fffffULL;
    os_sinit_data->vtd_pmr_hi_base = min_hi_ram;
    os_sinit_data->vtd_pmr_hi_size = hi_size;
}

tb_error_t txt_verify_platform(void)
{
    txt_heap_t *txt_heap;

    /* check is TXT_RESET.STS is set, since if it is SENTER will fail */
    txt_ests_t ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    if ( ests.txt_reset_sts ) {
        printk("TXT_RESET.STS is set and SENTER is disabled (0x%02Lx)\n",
               ests._raw);
        return TB_ERR_SMX_NOT_SUPPORTED;
    }

    /* verify BIOS to OS data */
    txt_heap = get_txt_heap();
    if ( !verify_bios_data(txt_heap) )
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
            
    /* verify that VT-d PMRs were really set as required */
    if ( !verify_vtd_pmrs(txt_heap) )
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
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
