/*
 * integrity.c: routines for memory integrity measurement & 
 *          verification. Memory integrity is protected with tpm seal
 *
 * Copyright (c) 2007-2008, Intel Corporation
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

/* put in .data section to that they aren't cleared on S3 resume */

/* hashes that are used to restore DRTM PCRs in S3 resume */
__data vl_hashes_t g_vl_msmnts;

static __data uint8_t  sealed_vl[512];
static __data uint32_t sealed_vl_size;

/* PCR 17+18 values post-launch and before extending (used to seal verified
   launch hashes and memory integrity UMAC) */
static __data tpm_pcr_value_t post_launch_pcr17, post_launch_pcr18;


extern bool hash_policy(tb_hash_t *hash, uint8_t hash_alg);

static bool extend_pcrs(void)
{
    tpm_pcr_value_t pcr17, pcr18;

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    printk("PCRs before extending:\n");
    printk("  PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("  PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);

    for ( int i = 0; i < g_vl_msmnts.num_entries; i++ ) {
        if ( tpm_pcr_extend(2, g_vl_msmnts.entries[i].pcr,
                            (tpm_pcr_value_t *)&g_vl_msmnts.entries[i].hash,
                            NULL) != TPM_SUCCESS )
            return false;
    }

    tpm_pcr_read(2, 17, &pcr17);
    tpm_pcr_read(2, 18, &pcr18);
    printk("PCRs after extending:\n");
    printk("  PCR 17: "); print_hash((tb_hash_t *)&pcr17, TB_HALG_SHA1);
    printk("  PCR 18: "); print_hash((tb_hash_t *)&pcr18, TB_HALG_SHA1);

    return true;
}

static bool create_policymsmnts_hash(tb_hash_t *hash)
{
    /* first hash g_vl_msmnts */
    memset(hash, 0, sizeof(*hash));
    if ( !hash_buffer((const unsigned char *)&g_vl_msmnts, sizeof(g_vl_msmnts),
                      hash, TB_HALG_SHA1) ) {
        printk("failed to hash g_vl_msmnts\n");
        return false;
    }
    /* then hash policy */
    tb_hash_t pol_hash;
    memset(&pol_hash, 0, sizeof(pol_hash));
    if ( !hash_policy(&pol_hash, TB_HALG_SHA1) ) {
        printk("failed to hash policy\n");
        return false;
    }
    /* now extend the first hash with the second */
    if ( !extend_hash(hash, &pol_hash, TB_HALG_SHA1) ) {
        printk("failed to extend hash\n");
        return false;
    }
    return true;
}

/*
 * DRTM measurements (e.g. policy control field, policy, modules) and current
 * policy (to prevent rollback) are sealed to PCRs 17+18 with post-launch
 * values (i.e. before extending with above)
 */
bool seal_initial_measurements(void)
{
    uint8_t pcr_indcs_create[]  = {17, 18};
    uint8_t pcr_indcs_release[] = {17, 18};
    const tpm_pcr_value_t *pcr_values_release[] = {&post_launch_pcr17,
                                                   &post_launch_pcr18};

    /* we need to seal g_vl_msmnts and the current policy (but TPM_Seal can
       only seal small data like key or hash), so seal hash of hashes */
    tb_hash_t hashes_hash;
    if ( !create_policymsmnts_hash(&hashes_hash) )
        return false;

    /* read PCR 17/18 */
    if ( tpm_pcr_read(2, 17, &post_launch_pcr17) != TPM_SUCCESS )
        return false;
    if ( tpm_pcr_read(2, 18, &post_launch_pcr18) != TPM_SUCCESS )
        return false;

    /* seal to locality 2, PCRs 17/18 */
    sealed_vl_size = sizeof(sealed_vl);
    if ( tpm_seal(2, TPM_LOC_TWO,
                  ARRAY_SIZE(pcr_indcs_create), pcr_indcs_create,
                  ARRAY_SIZE(pcr_indcs_release), pcr_indcs_release,
                  pcr_values_release, 
                  sizeof(hashes_hash), (const uint8_t *)&hashes_hash,
                  &sealed_vl_size, sealed_vl) != TPM_SUCCESS )
        return false;

    if ( !extend_pcrs() )
        return false;

    return true;
}

/*
 * verify sealed VL msmnts and policy, then re-extend hashes
 *
 * this must be called post-launch but before extending any modules or other
 * measurements into PCRs
 */
bool verify_integrity(void)
{
    uint32_t data_size;

    /*
     * unseal and verify VL measurements
     */

    /* sealed data is hash of (hash of g_vl_msmnts || hash of policy) */
    tb_hash_t sealed_hash;
    data_size = sizeof(sealed_hash);
    if ( tpm_unseal(2, sealed_vl_size, sealed_vl,
                    &data_size, (uint8_t *)&sealed_hash) != TPM_SUCCESS )
        return false;
    if ( data_size != sizeof(tb_hash_t) ) {
        printk("unsealed data size mismatch\n");
        return false;
    }

    /* verify that VL measurements and current policy match unsealed hash */
    tb_hash_t hashes_hash;
    if ( !create_policymsmnts_hash(&hashes_hash) )
        return false;
    if ( !are_hashes_equal(&sealed_hash, &hashes_hash, TB_HALG_SHA1) ) {
        printk("sealed hash does not match current hash\n");
        return false;
    }

    /* re-extend PCRs with VL measurements */
    if ( !extend_pcrs() )
        return false;

    return true;
}

void display_vl_msmnts(void)
{
    printk("g_vl_msmnts:\n");
    for ( int i = 0; i < g_vl_msmnts.num_entries; i++ ) {
        printk("\t PCR %d: ", g_vl_msmnts.entries[i].pcr);
        print_hash(&g_vl_msmnts.entries[i].hash, TB_HALG_SHA1);
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
