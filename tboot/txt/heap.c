/*
 * heap.c: fns for verifying and printing the Intel(r) TXT heap data structs
 *
 * Copyright (c) 2003-2011, Intel Corporation
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

#ifndef IS_INCLUDED
#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <compiler.h>
#include <string.h>
#include <printk.h>
#include <multiboot.h>
#include <uuid.h>
#include <mle.h>
#include <misc.h>
#include <hash.h>
#include <txt/mtrrs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#endif

/*
 * extended data elements
 */

/* HEAP_BIOS_SPEC_VER_ELEMENT */
static void print_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
    const heap_bios_spec_ver_elt_t *bios_spec_ver_elt =
        (const heap_bios_spec_ver_elt_t *)elt->data;

    printk("\t\t BIOS_SPEC_VER:\n");
    printk("\t\t     major: 0x%x\n", bios_spec_ver_elt->spec_ver_major);
    printk("\t\t     minor: 0x%x\n", bios_spec_ver_elt->spec_ver_minor);
    printk("\t\t     rev: 0x%x\n", bios_spec_ver_elt->spec_ver_rev);
}

static bool verify_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
    const heap_bios_spec_ver_elt_t *bios_spec_ver_elt =
        (const heap_bios_spec_ver_elt_t *)elt->data;

    if ( elt->size != sizeof(*elt) + sizeof(*bios_spec_ver_elt) ) {
        printk("HEAP_BIOS_SPEC_VER element has wrong size (%u)\n", elt->size);
        return false;
    }

    /* any values are allowed */
    return true;
}

/* HEAP_ACM_ELEMENT */
static void print_acm_elt(const heap_ext_data_element_t *elt)
{
    const heap_acm_elt_t *acm_elt = (const heap_acm_elt_t *)elt->data;

    printk("\t\t ACM:\n");
    printk("\t\t     num_acms: %u\n", acm_elt->num_acms);
    for ( unsigned int i = 0; i < acm_elt->num_acms; i++ )
        printk("\t\t     acm_addrs[%u]: 0x%jx\n", i, acm_elt->acm_addrs[i]);
}

static bool verify_acm_elt(const heap_ext_data_element_t *elt)
{
    const heap_acm_elt_t *acm_elt = (const heap_acm_elt_t *)elt->data;

    if ( elt->size != sizeof(*elt) + sizeof(*acm_elt) +
         acm_elt->num_acms*sizeof(uint64_t) ) {
        printk("HEAP_ACM element has wrong size (%u)\n", elt->size);
        return false;
    }

    /* no addrs is not error, but print warning */
    if ( acm_elt->num_acms == 0 )
        printk("HEAP_ACM element has no ACM addrs\n");

    for ( unsigned int i = 0; i < acm_elt->num_acms; i++ ) {
        if ( acm_elt->acm_addrs[i] == 0 ) {
            printk("HEAP_ACM element ACM addr (%u) is NULL\n", i);
            return false;
        }

        if ( acm_elt->acm_addrs[i] >= 0x100000000UL ) {
            printk("HEAP_ACM element ACM addr (%u) is >4GB (0x%jx)\n", i,
                   acm_elt->acm_addrs[i]);
            return false;
        }

        /* not going to check if ACM addrs are valid ACMs */
    }

    return true;
}

/* HEAP_CUSTOM_ELEMENT */
static void print_custom_elt(const heap_ext_data_element_t *elt)
{
    const heap_custom_elt_t *custom_elt = (const heap_custom_elt_t *)elt->data;

    printk("\t\t CUSTOM:\n");
    printk("\t\t     size: %u\n", elt->size);
    printk("\t\t     uuid: "); print_uuid(&custom_elt->uuid); printk("\n");
}

static bool verify_custom_elt(const heap_ext_data_element_t *elt)
{
    const heap_custom_elt_t *custom_elt = (const heap_custom_elt_t *)elt->data;

    if ( elt->size < sizeof(*elt) + sizeof(*custom_elt) ) {
        printk("HEAP_CUSTOM element has wrong size (%u)\n", elt->size);
        return false;
    }

    /* any values are allowed */
    return true;
}

/* HEAP_EVENT_LOG_POINTER_ELEMENT */
static inline void print_heap_hash(const sha1_hash_t hash)
{
    print_hash((const tb_hash_t *)hash, TB_HALG_SHA1);
}

void print_event(const tpm12_pcr_event_t *evt)
{
    printk("\t\t\t Event:\n");
    printk("\t\t\t     PCRIndex: %u\n", evt->pcr_index);
    printk("\t\t\t         Type: 0x%x\n", evt->type);
    printk("\t\t\t       Digest: ");
    print_heap_hash(evt->digest);
    printk("\t\t\t         Data: %u bytes", evt->data_size);
    print_hex("\t\t\t         ", evt->data, evt->data_size);
}

static void print_evt_log(const event_log_container_t *elog)
{
    printk("\t\t\t Event Log Container:\n");
    printk("\t\t\t     Signature: %s\n", elog->signature);
    printk("\t\t\t  ContainerVer: %u.%u\n",
           elog->container_ver_major, elog->container_ver_minor);
    printk("\t\t\t   PCREventVer: %u.%u\n",
           elog->pcr_event_ver_major, elog->pcr_event_ver_minor);
    printk("\t\t\t          Size: %u\n", elog->size);
    printk("\t\t\t  EventsOffset: [%u,%u)\n",
           elog->pcr_events_offset, elog->next_event_offset);

    const tpm12_pcr_event_t *curr, *next;
    curr = (tpm12_pcr_event_t *)((void*)elog + elog->pcr_events_offset);
    next = (tpm12_pcr_event_t *)((void*)elog + elog->next_event_offset);

    while ( curr < next ) {
        print_event(curr);
        curr = (void *)curr + sizeof(*curr) + curr->data_size;
    }
}

static bool verify_evt_log(const event_log_container_t *elog)
{
    if ( elog == NULL ) {
        printk("Event log container pointer is NULL\n");
        return false;
    }

    if ( memcmp(elog->signature, EVTLOG_SIGNATURE, sizeof(elog->signature)) ) {
        printk("Bad event log container signature: %s\n", elog->signature);
        return false;
    }

    if ( elog->size != MAX_EVENT_LOG_SIZE ) {
        printk("Bad event log container size: 0x%x\n", elog->size);
        return false;
    }

    /* no need to check versions */

    if ( elog->pcr_events_offset < sizeof(*elog) ||
         elog->next_event_offset < elog->pcr_events_offset ||
         elog->next_event_offset > elog->size ) {
        printk("Bad events offset range: [%u, %u)\n",
               elog->pcr_events_offset, elog->next_event_offset);
        return false;
    }

    return true;
}

static void print_evt_log_ptr_elt(const heap_ext_data_element_t *elt)
{
    const heap_event_log_ptr_elt_t *elog_elt =
              (const heap_event_log_ptr_elt_t *)elt->data;

    printk("\t\t EVENT_LOG_POINTER:\n");
    printk("\t\t       size: %u\n", elt->size);
    printk("\t\t  elog_addr: 0x%jx\n", elog_elt->event_log_phys_addr);

    if ( elog_elt->event_log_phys_addr )
        print_evt_log((event_log_container_t *)(unsigned long)
                      elog_elt->event_log_phys_addr);
}

static bool verify_evt_log_ptr_elt(const heap_ext_data_element_t *elt)
{
    const heap_event_log_ptr_elt_t *elog_elt =
              (const heap_event_log_ptr_elt_t *)elt->data;

    if ( elt->size != sizeof(*elt) + sizeof(*elog_elt) ) {
        printk("HEAP_EVENT_LOG_POINTER element has wrong size (%u)\n",
               elt->size);
        return false;
    }

    return verify_evt_log((event_log_container_t *)(unsigned long)
                          elog_elt->event_log_phys_addr);
}

static void print_ext_data_elts(const heap_ext_data_element_t elts[])
{
    const heap_ext_data_element_t *elt = elts;

    printk("\t ext_data_elts[]:\n");
    while ( elt->type != HEAP_EXTDATA_TYPE_END ) {
        switch ( elt->type ) {
            case HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
                print_bios_spec_ver_elt(elt);
                break;
            case HEAP_EXTDATA_TYPE_ACM:
                print_acm_elt(elt);
                break;
            case HEAP_EXTDATA_TYPE_CUSTOM:
                print_custom_elt(elt);
                break;
            case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
                print_evt_log_ptr_elt(elt);
                break;
            default:
                printk("\t\t unknown element:  type: %u, size: %u\n",
                       elt->type, elt->size);
                break;
        }
        elt = (void *)elt + elt->size;
    }
}

static bool verify_ext_data_elts(const heap_ext_data_element_t elts[],
                                 size_t elts_size)
{
    const heap_ext_data_element_t *elt = elts;

    while ( true ) {
        if ( elts_size < sizeof(*elt) ) {
            printk("heap ext data elements too small\n");
            return false;
        }
        switch ( elt->type ) {
            case HEAP_EXTDATA_TYPE_END:
                return true;
            case HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
                if ( !verify_bios_spec_ver_elt(elt) )
                    return false;
                break;
            case HEAP_EXTDATA_TYPE_ACM:
                if ( !verify_acm_elt(elt) )
                    return false;
                break;
            case HEAP_EXTDATA_TYPE_CUSTOM:
                if ( !verify_custom_elt(elt) )
                    return false;
                break;
            case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
                if ( !verify_evt_log_ptr_elt(elt) )
                    return false;
                break;
            default:
                printk("unknown element:  type: %u, size: %u\n", elt->type,
                       elt->size);
                break;
        }
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }
    return true;
}


static void print_bios_data(const bios_data_t *bios_data)
{
    printk("bios_data (@%p, %jx):\n", bios_data,
           *((uint64_t *)bios_data - 1));
    printk("\t version: %u\n", bios_data->version);
    printk("\t bios_sinit_size: 0x%x (%u)\n", bios_data->bios_sinit_size,
           bios_data->bios_sinit_size);
    printk("\t lcp_pd_base: 0x%jx\n", bios_data->lcp_pd_base);
    printk("\t lcp_pd_size: 0x%jx (%ju)\n", bios_data->lcp_pd_size,
           bios_data->lcp_pd_size);
    printk("\t num_logical_procs: %u\n", bios_data->num_logical_procs);
    if ( bios_data->version >= 3 )
        printk("\t flags: 0x%08jx\n", bios_data->flags);
    if ( bios_data->version >= 4 )
        print_ext_data_elts(bios_data->ext_data_elts);
}

bool verify_bios_data(const txt_heap_t *txt_heap)
{
    uint64_t heap_base = read_pub_config_reg(TXTCR_HEAP_BASE);
    uint64_t heap_size = read_pub_config_reg(TXTCR_HEAP_SIZE);
    printk("TXT.HEAP.BASE: 0x%jx\n", heap_base);
    printk("TXT.HEAP.SIZE: 0x%jx (%ju)\n", heap_size, heap_size);

    /* verify that heap base/size are valid */
    if ( txt_heap == NULL || heap_base == 0 || heap_size == 0 )
        return false;

    /* check size */
    uint64_t size = get_bios_data_size(txt_heap);
    if ( size == 0 ) {
        printk("BIOS data size is 0\n");
        return false;
    }
    if ( size > heap_size ) {
        printk("BIOS data size is larger than heap size "
               "(%jx, heap size=%jx)\n", size, heap_size);
        return false;
    }

    bios_data_t *bios_data = get_bios_data_start(txt_heap);

    /* check version */
    if ( bios_data->version < 2 ) {
        printk("unsupported BIOS data version (%u)\n", bios_data->version);
        return false;
    }
    /* we assume backwards compatibility but print a warning */
    if ( bios_data->version > 4 )
        printk("unsupported BIOS data version (%u)\n", bios_data->version);

    /* all TXT-capable CPUs support at least 2 cores */
    if ( bios_data->num_logical_procs < 2 ) {
        printk("BIOS data has incorrect num_logical_procs (%u)\n",
               bios_data->num_logical_procs);
        return false;
    }
    else if ( bios_data->num_logical_procs > NR_CPUS ) {
        printk("BIOS data specifies too many CPUs (%u)\n",
               bios_data->num_logical_procs);
        return false;
    }

    if ( bios_data->version >= 4 ) {
        if ( !verify_ext_data_elts(bios_data->ext_data_elts,
                                   size - sizeof(*bios_data)) )
            return false;
    }

    print_bios_data(bios_data);

    return true;
}

#ifndef IS_INCLUDED

static void print_os_mle_data(const os_mle_data_t *os_mle_data)
{
    printk("os_mle_data (@%p, %Lx):\n", os_mle_data,
           *((uint64_t *)os_mle_data - 1));
    printk("\t version: %u\n", os_mle_data->version);
    /* TBD: perhaps eventually print saved_mtrr_state field */
    printk("\t mbi: %p\n", os_mle_data->mbi);
}

static bool verify_os_mle_data(const txt_heap_t *txt_heap)
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
    if ( size != (sizeof(os_mle_data_t) + sizeof(size)) ) {
        printk("OS to MLE data size (%Lx) is not equal to "
               "os_mle_data_t size (%x)\n", size, sizeof(os_mle_data_t));
        return false;
    }

    os_mle_data = get_os_mle_data_start(txt_heap);

    /* check version */
    /* since this data is from our pre-launch to post-launch code only, it */
    /* should always be this */
    if ( os_mle_data->version != 3 ) {
        printk("unsupported OS to MLE data version (%u)\n",
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

void print_os_sinit_data(const os_sinit_data_t *os_sinit_data)
{
    printk("os_sinit_data (@%p, %Lx):\n", os_sinit_data,
           *((uint64_t *)os_sinit_data - 1));
    printk("\t version: %u\n", os_sinit_data->version);
    printk("\t mle_ptab: 0x%Lx\n", os_sinit_data->mle_ptab);
    printk("\t mle_size: 0x%Lx (%Lu)\n", os_sinit_data->mle_size,
           os_sinit_data->mle_size);
    printk("\t mle_hdr_base: 0x%Lx\n", os_sinit_data->mle_hdr_base);
    printk("\t vtd_pmr_lo_base: 0x%Lx\n", os_sinit_data->vtd_pmr_lo_base);
    printk("\t vtd_pmr_lo_size: 0x%Lx\n", os_sinit_data->vtd_pmr_lo_size);
    printk("\t vtd_pmr_hi_base: 0x%Lx\n", os_sinit_data->vtd_pmr_hi_base);
    printk("\t vtd_pmr_hi_size: 0x%Lx\n", os_sinit_data->vtd_pmr_hi_size);
    printk("\t lcp_po_base: 0x%Lx\n", os_sinit_data->lcp_po_base);
    printk("\t lcp_po_size: 0x%Lx (%Lu)\n", os_sinit_data->lcp_po_size,
           os_sinit_data->lcp_po_size);
    print_txt_caps("\t ", os_sinit_data->capabilities);
    if ( os_sinit_data->version >= 5 )
        printk("\t efi_rsdt_ptr: 0x%Lx\n", os_sinit_data->efi_rsdt_ptr);
    if ( os_sinit_data->version >= 6 )
        print_ext_data_elts(os_sinit_data->ext_data_elts);
}

static bool verify_os_sinit_data(const txt_heap_t *txt_heap)
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

    /* check version (but since we create this, it should always be OK) */
    if ( os_sinit_data->version < MIN_OS_SINIT_DATA_VER ||
         os_sinit_data->version > MAX_OS_SINIT_DATA_VER ) {
        printk("unsupported OS to SINIT data version (%u)\n",
               os_sinit_data->version);
        return false;
    }

    if ( size != calc_os_sinit_data_size(os_sinit_data->version) ) {
        printk("OS to SINIT data size (%Lx) does not match for version (%x)\n",
               size, sizeof(os_sinit_data_t));
        return false;
    }

    if ( os_sinit_data->version >= 6 ) {
        if ( !verify_ext_data_elts(os_sinit_data->ext_data_elts,
                                   size - sizeof(*os_sinit_data)) )
            return false;
    }

    print_os_sinit_data(os_sinit_data);

    return true;
}

static void print_sinit_mdrs(const sinit_mdr_t mdrs[], uint32_t num_mdrs)
{
    static const char *mem_types[] = {"GOOD", "SMRAM OVERLAY",
                                      "SMRAM NON-OVERLAY",
                                      "PCIE EXTENDED CONFIG", "PROTECTED"};

    printk("\t sinit_mdrs:\n");
    for ( unsigned int i = 0; i < num_mdrs; i++ ) {
        printk("\t\t %016Lx - %016Lx ", mdrs[i].base,
               mdrs[i].base + mdrs[i].length);
        if ( mdrs[i].mem_type < sizeof(mem_types)/sizeof(mem_types[0]) )
            printk("(%s)\n", mem_types[mdrs[i].mem_type]);
        else
            printk("(%d)\n", (int)mdrs[i].mem_type);
    }
}

static void print_sinit_mle_data(const sinit_mle_data_t *sinit_mle_data)
{
    printk("sinit_mle_data (@%p, %Lx):\n", sinit_mle_data,
           *((uint64_t *)sinit_mle_data - 1));
    printk("\t version: %u\n", sinit_mle_data->version);
    printk("\t bios_acm_id: \n\t");
    print_heap_hash(sinit_mle_data->bios_acm_id);
    printk("\t edx_senter_flags: 0x%08x\n",
           sinit_mle_data->edx_senter_flags);
    printk("\t mseg_valid: 0x%Lx\n", sinit_mle_data->mseg_valid);
    printk("\t sinit_hash:\n\t"); print_heap_hash(sinit_mle_data->sinit_hash);
    printk("\t mle_hash:\n\t"); print_heap_hash(sinit_mle_data->mle_hash);
    printk("\t stm_hash:\n\t"); print_heap_hash(sinit_mle_data->stm_hash);
    printk("\t lcp_policy_hash:\n\t");
        print_heap_hash(sinit_mle_data->lcp_policy_hash);
    printk("\t lcp_policy_control: 0x%08x\n",
           sinit_mle_data->lcp_policy_control);
    printk("\t rlp_wakeup_addr: 0x%x\n", sinit_mle_data->rlp_wakeup_addr);
    printk("\t num_mdrs: %u\n", sinit_mle_data->num_mdrs);
    printk("\t mdrs_off: 0x%x\n", sinit_mle_data->mdrs_off);
    printk("\t num_vtd_dmars: %u\n", sinit_mle_data->num_vtd_dmars);
    printk("\t vtd_dmars_off: 0x%x\n", sinit_mle_data->vtd_dmars_off);
    print_sinit_mdrs((sinit_mdr_t *)
                     (((void *)sinit_mle_data - sizeof(uint64_t)) +
                      sinit_mle_data->mdrs_off), sinit_mle_data->num_mdrs);
    if ( sinit_mle_data->version >= 8 )
        printk("\t proc_scrtm_status: 0x%08x\n",
               sinit_mle_data->proc_scrtm_status);
}

static bool verify_sinit_mle_data(const txt_heap_t *txt_heap)
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
        return false;
    }

    sinit_mle_data = get_sinit_mle_data_start(txt_heap);

    /* check version */
    sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    if ( sinit_mle_data->version < 6 ) {
        printk("unsupported SINIT to MLE data version (%u)\n",
               sinit_mle_data->version);
        return false;
    }
    else if ( sinit_mle_data->version > 8 ) {
        printk("unsupported SINIT to MLE data version (%u)\n",
               sinit_mle_data->version);
    }

    /* this data is generated by SINIT and so is implicitly trustworthy, */
    /* so we don't need to validate it's fields */

    print_sinit_mle_data(sinit_mle_data);

    return true;
}

bool verify_txt_heap(const txt_heap_t *txt_heap, bool bios_data_only)
{
    /* verify BIOS to OS data */
    if ( !verify_bios_data(txt_heap) )
        return false;

    if ( bios_data_only )
        return true;

    /* check that total size is within the heap */
    uint64_t size1 = get_bios_data_size(txt_heap);
    uint64_t size2 = get_os_mle_data_size(txt_heap);
    uint64_t size3 = get_os_sinit_data_size(txt_heap);
    uint64_t size4 = get_sinit_mle_data_size(txt_heap);

    /* overflow? */
    if ( plus_overflow_u64(size1, size2) ) {
        printk("TXT heap data size overflows\n");
        return false;
    }
    if ( plus_overflow_u64(size3, size4) ) {
        printk("TXT heap data size overflows\n");
        return false;
    }
    if ( plus_overflow_u64(size1 + size2, size3 + size4) ) {
        printk("TXT heap data size overflows\n");
        return false;
    }

    if ( (size1 + size2 + size3 + size4) >
         read_priv_config_reg(TXTCR_HEAP_SIZE) ) {
        printk("TXT heap data sizes (%Lx, %Lx, %Lx, %Lx) are larger than\n"
               "heap total size (%Lx)\n", size1, size2, size3, size4,
               read_priv_config_reg(TXTCR_HEAP_SIZE));
        return false;
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

#endif

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
