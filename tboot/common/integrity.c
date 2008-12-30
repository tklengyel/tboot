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
#include <hash.h>
#include <integrity.h>
#include <tpm.h>
#include <tboot.h>
#include <tb_policy.h>
#include <tb_error.h>

/* put in .data section to that they aren't cleared on launch */

/* hashes that are used to restore DRTM PCRs in S3 resume */
__data vl_hashes_t g_vl_hashes;

static __data uint8_t  sealed_vl[512];
static __data uint32_t sealed_vl_size;

static bool extend_pcrs(void)
{
    for ( int i = 0; i < g_vl_hashes.num_entries; i++ ) {
        if ( tpm_pcr_extend(2, g_vl_hashes.entries[i].pcr,
                            (tpm_pcr_value_t *)&g_vl_hashes.entries[i].hash,
                            NULL) != TPM_SUCCESS )
            return false;
    }

    return true;
}

bool seal_vl_hashes(void)
{  
    uint8_t pcr_indcs_create[2]  = {17, 18};
    uint8_t pcr_indcs_release[2] = {17, 18};
    tpm_pcr_value_t pcr17, pcr18;
    const tpm_pcr_value_t *pcr_values_release[2] = {&pcr17, &pcr18};


    /* need to create hash of g_vl_hashes, which is then sealed */
    /* (TPM_Seal can only seal small data like key or hash) */
    tb_hash_t hashes_hash;
    memset(&hashes_hash, 0, sizeof(hashes_hash));
    if ( !hash_buffer((const unsigned char *)&g_vl_hashes,
                      sizeof(g_vl_hashes), &hashes_hash, TB_HALG_SHA1) ) {
        printk("failed to hash g_vl_hashes\n");
        return false;
    }

    /* read PCR 17/18 */
    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    printk("PCRs before extending:\n");
    printk("  PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("  PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);

    /* seal to locality 2, PCRs 17/18 */
    sealed_vl_size = sizeof(sealed_vl);
    if ( tpm_seal(2, TPM_LOC_TWO, 2, pcr_indcs_create,
                  2, pcr_indcs_release, pcr_values_release, 
                  sizeof(hashes_hash), (const uint8_t *)&hashes_hash,
                  &sealed_vl_size, sealed_vl) != TPM_SUCCESS )
        return false;

    if ( !extend_pcrs() )
        return false;

    /* read PCR 17/18/19 */
    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    printk("PCRs after extending:\n");
    printk("  PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("  PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);

    return true;
}
    
bool verify_vl_integrity(void)
{
    uint32_t data_size;
    int i;

    /* sealed data is hash of g_vl_hashes */
    /* (TPM_Seal can only seal small data like key or hash) */
    tb_hash_t sealed_hash;

    /* unseal the blob */
    data_size = sizeof(sealed_hash);
    if ( tpm_unseal(2, sealed_vl_size, sealed_vl,
                    &data_size, (uint8_t *)&sealed_hash) != TPM_SUCCESS )
        return false;

    /* now verify unsealed hash */
    tb_hash_t hashes_hash;
    memset(&hashes_hash, 0, sizeof(hashes_hash));
    if ( data_size != sizeof(hashes_hash) ) {
        printk("unsealed data size mismatch\n");
        return false;
    }
    if ( !hash_buffer((const unsigned char *)&g_vl_hashes,
                      sizeof(g_vl_hashes), &hashes_hash, TB_HALG_SHA1) ) {
        printk("failed to hash g_vl_hashes\n");
        return false;
    }
    if ( !are_hashes_equal(&sealed_hash, &hashes_hash, TB_HALG_SHA1) ) {
        printk("sealed hash does not match current hash\n");
        return false;
    }

    printk("PCRs before S3 extending:\n");
    for ( i = 0; i < g_vl_hashes.num_entries; i++ ) {
        tb_hash_t hash;
        tpm_pcr_read(2, g_vl_hashes.entries[i].pcr, (tpm_pcr_value_t *)&hash);
        print_hash(&hash, TB_HALG_SHA1);
    }

    /* extend PCRs with saved hashes */
    if ( !extend_pcrs() )
        return false;

    printk("PCRs after S3 extending:\n");
    for ( i = 0; i < g_vl_hashes.num_entries; i++ ) {
        tb_hash_t hash;
        tpm_pcr_read(2, g_vl_hashes.entries[i].pcr, (tpm_pcr_value_t *)&hash);
        print_hash(&hash, TB_HALG_SHA1);
    }

    return true;
}

void display_vl_hashes(void)
{
    printk("g_vl_hashes:\n");
    for ( int i = 0; i < g_vl_hashes.num_entries; i++ ) {
        printk("\t PCR %d: ", g_vl_hashes.entries[i].pcr);
        print_hash(&g_vl_hashes.entries[i].hash, TB_HALG_SHA1);
    }
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
