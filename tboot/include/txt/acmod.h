/*
 * acmod.c: support functions for use of Intel(r) TXT Authenticated
 *          Code (AC) Modules
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

#ifndef __TXT_ACMOD_H__
#define __TXT_ACMOD_H__

#include <types.h>
#include <stdbool.h>
#include <txt/config_regs.h>

/*
 * authenticated code (AC) module header (ver 0.0)
 */

typedef struct {
    uint32_t module_type;
    uint32_t header_len;
    uint32_t header_ver;
    uint32_t module_id;
    uint32_t module_vendor;
    uint32_t date;
    uint32_t size;
    uint32_t reserved1;
    uint32_t code_control;
    uint32_t error_entry_point;
    uint32_t gdt_limit;
    uint32_t gdt_base;
    uint32_t seg_sel;
    uint32_t entry_point;
    uint8_t  reserved2[64];
    uint32_t key_size;
    uint32_t scratch_size;
    uint8_t  rsa2048_pubkey[256];
    uint32_t pub_exp;
    uint8_t  rsa2048_sig[256];
    uint32_t scratch[143];
    uint8_t  user_area[];
} acm_hdr_t;

/* value of mod_type field */
#define ACM_TYPE_CHIPSET        0x02

/* value of module_vendor field */
#define ACM_VENDOR_INTEL        0x8086

extern bool is_sinit_acmod(void *acmod_base, uint32_t acmod_size);
extern bool does_acmod_match_chipset(acm_hdr_t* hdr);
extern acm_hdr_t *copy_sinit(acm_hdr_t *sinit);
extern bool verify_acmod(acm_hdr_t *acm_hdr);
extern void set_mtrrs_for_acmod(acm_hdr_t *hdr);
extern uint32_t get_supported_os_sinit_data_ver(acm_hdr_t* hdr);

#endif /* __TXT_ACMOD_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
