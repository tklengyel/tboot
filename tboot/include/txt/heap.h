/*
 * heap.h: Intel(r) TXT heap definitions
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

#ifndef __TXT_HEAP_H__
#define __TXT_HEAP_H__

#include <types.h>
#include <multiboot.h>
#include <txt/mtrrs.h>

/*
 * data-passing structures contained in TXT heap:
 *   - BIOS to OS/loader
 *   - OS/loader to MLE
 *   - OS/loader to SINIT
 *   - SINIT to MLE
 */

/*
 * BIOS to OS/loader structure
 *   - not used by current Xen
 */
typedef struct {
    uint32_t version;           /* SDP3/TEP=0x00, WB=0x02 */
    uint32_t bios_sinit_size;
    union {
        struct {
            uint64_t  lcp_pd_base;
            uint64_t  lcp_pd_size;
            uint32_t  num_logical_procs;
        } v2;
    };
} bios_os_data_t;

/*
 * OS/loader to MLE structure v1
 *   - private to Xen (so can be any format we need)
 */
typedef struct {
    uint32_t          version;           /* will be 0x01 */
    mtrr_state_t      saved_mtrr_state;  /* saved prior to changes for SINIT */
    multiboot_info_t* mbi;               /* needs to be restored to ebx */
    uint32_t          saved_misc_enable_msr;  /* saved prior to SENTER */
} os_mle_data_t;

/*
 * OS/loader to SINIT structure v1
 */
typedef struct {
    uint32_t version;           /* SDP3/TEP=0x01, WB=0x03 */
    uint32_t reserved;
    uint64_t mle_ptab;
    uint64_t mle_size;
    uint64_t mle_hdr_base;
    union {
        struct {
            uint64_t  vtd_pmr_lo_base;
            uint64_t  vtd_pmr_lo_size;
            uint64_t  vtd_pmr_hi_base;
            uint64_t  vtd_pmr_hi_size;
            uint64_t  lcp_po_base;
            uint64_t  lcp_po_size;
        } v3;
    };
} os_sinit_data_t;

/*
 * SINIT to MLE structure
 */
#define MDR_MEMTYPE_GOOD                0x00
#define MDR_MEMTYPE_SMM_OVERLAY         0x01
#define MDR_MEMTYPE_SMM_NONOVERLAY      0x02
#define MDR_MEMTYPE_PCIE_CONFIG_SPACE   0x03
#define MDR_MEMTYPE_PROTECTED           0x04

typedef struct __attribute__ ((packed)) {
    uint64_t  base;
    uint64_t  length;
    uint8_t   mem_type;
    uint8_t   reserved[7];
} sinit_mdr_t;

#define SHA1_SIZE      20
typedef uint8_t   sha1_hash_t[SHA1_SIZE];

typedef struct {
    uint32_t     version;           /* SDP3/TEP=0x01, WB=0x03/0x05 */
    union {
        struct {
            uint32_t     num_mdrs;
            sinit_mdr_t  mdrs[];
        } v1;
        struct {
            sha1_hash_t  bios_acm_id;
            uint32_t     edx_senter_flags;
            uint64_t     mseg_valid;
            sha1_hash_t  sinit_hash;
            sha1_hash_t  mle_hash;
            sha1_hash_t  stm_hash;
            sha1_hash_t  lcp_policy_hash;
            uint32_t     lcp_policy_control;
            uint64_t     reserved;
            uint32_t     num_mdrs;
            uint32_t     mdrs_off;
            uint32_t     num_vtd_dmars;
            uint32_t     vtd_dmars_off;
        } v5;
    };
} sinit_mle_data_t;


/*
 * TXT heap data format and field accessor fns
 */

/*
 * offset                 length                      field
 * ------                 ------                      -----
 *  0                      8                          bios_os_data_size
 *  8                      bios_os_data_size - 8      bios_os_data
 *
 *  bios_os_data_size      8                          os_mle_data_size
 *  bios_os_data_size +    os_mle_data_size - 8       os_mle_data
 *   8
 *
 *  bios_os_data_size +    8                          os_sinit_data_size
 *   os_mle_data_size
 *  bios_os_data_size +    os_sinit_data_size - 8     os_sinit_data
 *   os_mle_data_size +
 *   8
 *
 *  bios_os_data_size +    8                          sinit_mle_data_size
 *   os_mle_data_size +
 *   os_sinit_data_size
 *  bios_os_data_size +    sinit_mle_data_size - 8    sinit_mle_data
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

static inline uint64_t get_bios_os_data_size(txt_heap_t *heap)
{
    return *(uint64_t *)heap;
}

static inline bios_os_data_t *get_bios_os_data_start(txt_heap_t *heap)
{
    return (bios_os_data_t *)((char*)heap + sizeof(uint64_t));
}

static inline uint64_t get_os_mle_data_size(txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_os_data_size(heap));
}

static inline os_mle_data_t *get_os_mle_data_start(txt_heap_t *heap)
{
    return (os_mle_data_t *)(heap + get_bios_os_data_size(heap) +
                              sizeof(uint64_t));
}

static inline uint64_t get_os_sinit_data_size(txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_os_data_size(heap) +
                         get_os_mle_data_size(heap));
}

static inline os_sinit_data_t *get_os_sinit_data_start(txt_heap_t *heap)
{
    return (os_sinit_data_t *)(heap + get_bios_os_data_size(heap) +
                               get_os_mle_data_size(heap) +
                               sizeof(uint64_t));
}

static inline uint64_t get_sinit_mle_data_size(txt_heap_t *heap)
{
    return *(uint64_t *)(heap + get_bios_os_data_size(heap) +
                         get_os_mle_data_size(heap) +
                         get_os_sinit_data_size(heap));
}

static inline sinit_mle_data_t *get_sinit_mle_data_start(txt_heap_t *heap)
{
    return (sinit_mle_data_t *)(heap + get_bios_os_data_size(heap) +
                                get_os_mle_data_size(heap) +
                                get_os_sinit_data_size(heap) +
                                sizeof(uint64_t));
}

#endif      /* __TXT_HEAP_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
