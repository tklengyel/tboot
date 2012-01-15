/*
 * heap.h: Intel(r) TXT heap definitions
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

#ifndef __TXT_HEAP_H__
#define __TXT_HEAP_H__

/*
 * Extensible TXT heap data structure
 */

typedef struct __packed {
    uint32_t   type;
    uint32_t   size;
    uint8_t    data[];
} heap_ext_data_element_t;

/*
 * HEAP_END_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_END             0

/* size == 8; there is no data[] */

/*
 * HEAP_BIOS_SPEC_VER_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_BIOS_SPEC_VER   1

typedef struct __packed {
    uint16_t   spec_ver_major;
    uint16_t   spec_ver_minor;
    uint16_t   spec_ver_rev;
} heap_bios_spec_ver_elt_t;

/*
 * HEAP_ACM_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_ACM             2

typedef struct __packed {
    uint32_t   num_acms;
    uint64_t   acm_addrs[];
} heap_acm_elt_t;

/*
 * HEAP_CUSTOM_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_CUSTOM          4

typedef struct __packed {
    uuid_t     uuid;
    uint8_t    data[];
} heap_custom_elt_t;

/*
 * HEAP_EVENT_LOG_POINTER_ELEMENT
 */
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR   5

typedef struct __packed {
    uint64_t   event_log_phys_addr;
} heap_event_log_ptr_elt_t;

typedef struct __packed {
    uint32_t pcr_index;
    uint32_t type;
    sha1_hash_t digest;
    uint32_t data_size;
    uint8_t data[];
} tpm12_pcr_event_t;

#define EVTLOG_SIGNATURE "TXT Event Container\0"
#define EVTLOG_CNTNR_MAJOR_VER 1
#define EVTLOG_CNTNR_MINOR_VER 0
#define EVTLOG_EVT_MAJOR_VER 1
#define EVTLOG_EVT_MINOR_VER 0
typedef struct __packed {
    uint8_t signature[20];
    uint8_t reserved[12];
    uint8_t container_ver_major;
    uint8_t container_ver_minor;
    uint8_t pcr_event_ver_major;
    uint8_t pcr_event_ver_minor;
    uint32_t size;
    uint32_t pcr_events_offset;
    uint32_t next_event_offset;
    tpm12_pcr_event_t pcr_events[];
} event_log_container_t;

/*
 * data-passing structures contained in TXT heap:
 *   - BIOS
 *   - OS/loader to MLE
 *   - OS/loader to SINIT
 *   - SINIT to MLE
 */

/*
 * BIOS structure
 */
typedef struct __packed {
    uint32_t  version;              /* currently 2-4 */
    uint32_t  bios_sinit_size;
    uint64_t  lcp_pd_base;
    uint64_t  lcp_pd_size;
    uint32_t  num_logical_procs;
    /* versions >= 3 */
    uint64_t  flags;
    /* versions >= 4 */
    heap_ext_data_element_t  ext_data_elts[];
} bios_data_t;

/*
 * OS/loader to MLE structure
 *   - private to tboot (so can be any format we need)
 */
#define MAX_LCP_PO_DATA_SIZE     64*1024  /* 64k */
#define MAX_EVENT_LOG_SIZE       4*1024   /* 4k */

typedef struct __packed {
    uint32_t          version;           /* currently 3 */
    mtrr_state_t      saved_mtrr_state;  /* saved prior to changes for SINIT */
    multiboot_info_t* mbi;               /* needs to be restored to ebx */
    uint32_t          saved_misc_enable_msr;  /* saved prior to SENTER */
                                         /* PO policy data */
    uint8_t           lcp_po_data[MAX_LCP_PO_DATA_SIZE];
                                         /* buffer for tpm event log */
    uint8_t           event_log_buffer[MAX_EVENT_LOG_SIZE];
} os_mle_data_t;

#define MIN_OS_SINIT_DATA_VER    4
#define MAX_OS_SINIT_DATA_VER    6
/*
 * OS/loader to SINIT structure
 */
typedef struct __packed {
    uint32_t    version;           /* currently 4-6 */
    uint32_t    reserved;
    uint64_t    mle_ptab;
    uint64_t    mle_size;
    uint64_t    mle_hdr_base;
    uint64_t    vtd_pmr_lo_base;
    uint64_t    vtd_pmr_lo_size;
    uint64_t    vtd_pmr_hi_base;
    uint64_t    vtd_pmr_hi_size;
    uint64_t    lcp_po_base;
    uint64_t    lcp_po_size;
    txt_caps_t  capabilities;
    /* versions >= 5 */
    uint64_t    efi_rsdt_ptr;
    /* versions >= 6 */
    heap_ext_data_element_t  ext_data_elts[];
} os_sinit_data_t;

/*
 * SINIT to MLE structure
 */
#define MDR_MEMTYPE_GOOD                0x00
#define MDR_MEMTYPE_SMM_OVERLAY         0x01
#define MDR_MEMTYPE_SMM_NONOVERLAY      0x02
#define MDR_MEMTYPE_PCIE_CONFIG_SPACE   0x03
#define MDR_MEMTYPE_PROTECTED           0x04

typedef struct __packed {
    uint64_t  base;
    uint64_t  length;
    uint8_t   mem_type;
    uint8_t   reserved[7];
} sinit_mdr_t;

typedef struct __packed {
    uint32_t     version;             /* currently 6-8 */
    sha1_hash_t  bios_acm_id;
    uint32_t     edx_senter_flags;
    uint64_t     mseg_valid;
    sha1_hash_t  sinit_hash;
    sha1_hash_t  mle_hash;
    sha1_hash_t  stm_hash;
    sha1_hash_t  lcp_policy_hash;
    uint32_t     lcp_policy_control;
    uint32_t     rlp_wakeup_addr;
    uint32_t     reserved;
    uint32_t     num_mdrs;
    uint32_t     mdrs_off;
    uint32_t     num_vtd_dmars;
    uint32_t     vtd_dmars_off;
    /* versions >= 8 */
    uint32_t     proc_scrtm_status;
} sinit_mle_data_t;


/*
 * TXT heap data format and field accessor fns
 */

/*
 * offset                 length                      field
 * ------                 ------                      -----
 *  0                      8                          bios_data_size
 *  8                      bios_data_size - 8      bios_data
 *
 *  bios_data_size      8                          os_mle_data_size
 *  bios_data_size +    os_mle_data_size - 8       os_mle_data
 *   8
 *
 *  bios_data_size +    8                          os_sinit_data_size
 *   os_mle_data_size
 *  bios_data_size +    os_sinit_data_size - 8     os_sinit_data
 *   os_mle_data_size +
 *   8
 *
 *  bios_data_size +    8                          sinit_mle_data_size
 *   os_mle_data_size +
 *   os_sinit_data_size
 *  bios_data_size +    sinit_mle_data_size - 8    sinit_mle_data
 *   os_mle_data_size +
 *   os_sinit_data_size +
 *   8
 */

typedef void   txt_heap_t;

/* this is a common use with annoying casting, so make it an inline */
static inline txt_heap_t *get_txt_heap(void)
{
    return (txt_heap_t *)(unsigned long)read_pub_config_reg(TXTCR_HEAP_BASE);
}

static inline uint64_t get_bios_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)heap;
}

static inline bios_data_t *get_bios_data_start(const txt_heap_t *heap)
{
    return (bios_data_t *)((char*)heap + sizeof(uint64_t));
}

static inline uint64_t get_os_mle_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap));
}

static inline os_mle_data_t *get_os_mle_data_start(const txt_heap_t *heap)
{
    return (os_mle_data_t *)(heap + get_bios_data_size(heap) +
                              sizeof(uint64_t));
}

static inline uint64_t get_os_sinit_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap) +
                         get_os_mle_data_size(heap));
}

static inline os_sinit_data_t *get_os_sinit_data_start(const txt_heap_t *heap)
{
    return (os_sinit_data_t *)(heap + get_bios_data_size(heap) +
                               get_os_mle_data_size(heap) +
                               sizeof(uint64_t));
}

static inline uint64_t get_sinit_mle_data_size(const txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_data_size(heap) +
                         get_os_mle_data_size(heap) +
                         get_os_sinit_data_size(heap));
}

static inline sinit_mle_data_t *get_sinit_mle_data_start(const txt_heap_t *heap)
{
    return (sinit_mle_data_t *)(heap + get_bios_data_size(heap) +
                                get_os_mle_data_size(heap) +
                                get_os_sinit_data_size(heap) +
                                sizeof(uint64_t));
}

/*
 * Make sure version is in [MIN_OS_SINIT_DATA_VER, MAX_OS_SINIT_DATA_VER]
 * before calling calc_os_sinit_data_size
 */
static inline uint64_t calc_os_sinit_data_size(uint32_t version)
{
    uint64_t size[] = {
        offsetof(os_sinit_data_t, efi_rsdt_ptr) + sizeof(uint64_t),
        sizeof(os_sinit_data_t) + sizeof(uint64_t),
        sizeof(os_sinit_data_t) + sizeof(uint64_t) +
            2 * sizeof(heap_ext_data_element_t) +
            sizeof(heap_event_log_ptr_elt_t)
   };

   return size[version - MIN_OS_SINIT_DATA_VER];
}

extern bool verify_txt_heap(const txt_heap_t *txt_heap, bool bios_data_only);
extern bool verify_bios_data(const txt_heap_t *txt_heap);
extern void print_os_sinit_data(const os_sinit_data_t *os_sinit_data);

#endif      /* __TXT_HEAP_H__ */


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
