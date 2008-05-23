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

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/* tcb hashes (in policy.c) */
extern tcb_hashes_t g_tcb_hashes;

/* defined in policy.c */
extern void re_evaluate_all_policies(void);

static uint8_t  sealed_tcb[512];
static uint32_t sealed_tcb_size;

static tpm_pcr_value_t saved_pcr17, saved_pcr18, saved_pcr19;

static void extend_pcrs(void)
{
    tpm_pcr_extend(2, 17, (tpm_pcr_value_t *)&g_tcb_hashes.policy, NULL);
    tpm_pcr_extend(2, 18, (tpm_pcr_value_t *)&g_tcb_hashes.vmm, NULL);
    tpm_pcr_extend(2, 19, (tpm_pcr_value_t *)&g_tcb_hashes.dom0, NULL);
}

void seal_tcb(void)
{  
    uint8_t pcr_indcs_create[2]  = {17, 18};
    uint8_t pcr_indcs_release[2] = {17, 18};
    const tpm_pcr_value_t *pcr_values_release[2] = 
            {&saved_pcr17, &saved_pcr18};

    sealed_tcb_size = sizeof(sealed_tcb);

    /* read PCR 17/18/19 */
    tpm_pcr_read(2, 17, &saved_pcr17);
    tpm_pcr_read(2, 18, &saved_pcr18);
    tpm_pcr_read(2, 19, &saved_pcr19);

    printk("saved PCRs:\n");
    printk("PCR 17: "); print_hash((tb_hash_t *)&saved_pcr17, TB_HALG_SHA1);
    printk("PCR 18: "); print_hash((tb_hash_t *)&saved_pcr18, TB_HALG_SHA1);
    printk("PCR 19: "); print_hash((tb_hash_t *)&saved_pcr19, TB_HALG_SHA1);

    /* seal to locality 2, pcr 17/18, generate sealed blob 1 */
    tpm_seal(2, TPM_LOC_TWO, 2, pcr_indcs_create,
             2, pcr_indcs_release, pcr_values_release, 
             sizeof(g_tcb_hashes), (const uint8_t *)&g_tcb_hashes,
             &sealed_tcb_size, sealed_tcb);

    extend_pcrs();
}
    
bool verify_mem_integrity(void)
{
    uint32_t data_size;
    tb_hash_t pcr17, pcr18, pcr19;

    /* Unseal the blobs */
    data_size = sizeof(g_tcb_hashes);
    tpm_unseal(2, sealed_tcb_size, sealed_tcb,
               &data_size, (uint8_t *)&g_tcb_hashes);

    /* Read PCR17~19 into temp var */
    tpm_pcr_read(2, 17, (tpm_pcr_value_t *)&pcr17.sha1);
    tpm_pcr_read(2, 18, (tpm_pcr_value_t *)&pcr18.sha1);
    tpm_pcr_read(2, 19, (tpm_pcr_value_t *)&pcr19.sha1);

    /* Extend tmp_pcr17~19 with saved hashes in blob 1 */
    extend_hash(&pcr17, &g_tcb_hashes.policy, TB_HALG_SHA1);
    extend_hash(&pcr18, &g_tcb_hashes.vmm,    TB_HALG_SHA1);
    extend_hash(&pcr19, &g_tcb_hashes.dom0,   TB_HALG_SHA1);
    printk("Next values for pcr 17/18/19:\n");
    print_hash(&pcr17, TB_HALG_SHA1);
    print_hash(&pcr18, TB_HALG_SHA1);
    print_hash(&pcr19, TB_HALG_SHA1);

    /* Extend PCR 17~19 with saved hashes */
    extend_pcrs();

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
