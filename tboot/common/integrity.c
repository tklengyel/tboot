/*
 * integrity.c: routines for memory integrity measurement & 
 *          verification. Memory integrity is protected with tpm seal
 *
 * Copyright (c) 2007, Intel Corporation
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
#include <printk.h>
#include <misc.h>
#include <compiler.h>
#include <string2.h>
#include <integrity.h>
#include <tpm.h>
#include <tboot.h>
#include <hash.h>
#include <tb_policy.h>
#include <tb_error.h>

/* tcb hashes (in policy.c) */
extern tcb_hashes_t g_tcb_hashes;

/* defined in policy.c */
extern void re_evaluate_all_policies(void);

/* put in .data section to that they aren't cleared on launch */
static __data uint8_t  sealed_tcb[512];
static __data uint32_t sealed_tcb_size;

static bool extend_pcrs(void)
{
    if ( tpm_pcr_extend(2, 17, (tpm_pcr_value_t *)&g_tcb_hashes.policy, NULL)
         != TPM_SUCCESS )
        return false;
    if ( tpm_pcr_extend(2, 18, (tpm_pcr_value_t *)&g_tcb_hashes.vmm, NULL)
         != TPM_SUCCESS )
        return false;
    if ( tpm_pcr_extend(2, 19, (tpm_pcr_value_t *)&g_tcb_hashes.dom0, NULL)
         != TPM_SUCCESS )
        return false;

    return true;
}

bool seal_tcb(void)
{  
    uint8_t pcr_indcs_create[2]  = {17, 18};
    uint8_t pcr_indcs_release[2] = {17, 18};
    tpm_pcr_value_t pcr17, pcr18, pcr19;
    const tpm_pcr_value_t *pcr_values_release[2] = {&pcr17, &pcr18};

    sealed_tcb_size = sizeof(sealed_tcb);

    /* read PCR 17/18/19 */
    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);
    printk("PCRs before extending:\n");
    printk("PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);
    printk("PCR 19: "); print_hash((tb_hash_t *)&pcr19, TB_HALG_SHA1);

    /* seal to locality 2, pcr 17/18, generate sealed blob 1 */
    if ( tpm_seal(2, TPM_LOC_TWO, 2, pcr_indcs_create,
                  2, pcr_indcs_release, pcr_values_release, 
                  sizeof(g_tcb_hashes), (const uint8_t *)&g_tcb_hashes,
                  &sealed_tcb_size, sealed_tcb) != TPM_SUCCESS )
        return false;

    if ( !extend_pcrs() )
        return false;

    /* read PCR 17/18/19 */
    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    tpm_pcr_read(2, 19, &pcr19);
    printk("PCRs after extending:\n");
    printk("PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);
    printk("PCR 19: "); print_hash((tb_hash_t *)&pcr19, TB_HALG_SHA1);

    return true;
}
    
bool verify_mem_integrity(void)
{
    uint32_t data_size;
    tb_hash_t pcr17, pcr18, pcr19;

    /* Unseal the blobs */
    data_size = sizeof(g_tcb_hashes);
    if ( tpm_unseal(2, sealed_tcb_size, sealed_tcb,
                    &data_size, (uint8_t *)&g_tcb_hashes) != TPM_SUCCESS )
        return false;

    /* Read PCR17~19 into temp var */
    tpm_pcr_read(2, 17, (tpm_pcr_value_t *)&pcr17.sha1);
    tpm_pcr_read(2, 18, (tpm_pcr_value_t *)&pcr18.sha1);
    tpm_pcr_read(2, 19, (tpm_pcr_value_t *)&pcr19.sha1);
    printk("PCRs before S3 extending:\n");
    print_hash(&pcr17, TB_HALG_SHA1);
    print_hash(&pcr18, TB_HALG_SHA1);
    print_hash(&pcr19, TB_HALG_SHA1);

    /* Extend PCR 17~19 with saved hashes */
    if ( !extend_pcrs() )
        return false;

    tpm_pcr_read(2, 17, (tpm_pcr_value_t *)&pcr17.sha1);
    tpm_pcr_read(2, 18, (tpm_pcr_value_t *)&pcr18.sha1);
    tpm_pcr_read(2, 19, (tpm_pcr_value_t *)&pcr19.sha1);
    printk("PCRs after S3 extending:\n");
    print_hash(&pcr17, TB_HALG_SHA1);
    print_hash(&pcr18, TB_HALG_SHA1);
    print_hash(&pcr19, TB_HALG_SHA1);

    return true;
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
