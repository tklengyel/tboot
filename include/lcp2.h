/*
 * Copyright 2001 - 2010 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TXT_LCP2_H__
#define __TXT_LCP2_H__

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

/*--------- LCP reserved TPM NV Indices ------------*/
#define INDEX_LCP_OWN   0x40000001

/* for clients that only need the owner index */
#ifndef LCP_TBOOT_ONLY

#define INDEX_LCP_DEF   0x50000001
#define INDEX_AUX       0x50000002

/*------ Default Permission, size and locality for reserved Indices --------*/
#define PERMISSION_DEF  0x00002000
#define PERMISSION_OWN  0x00000002
#define PERMISSION_AUX  0x0

#define DATASIZE_POL    54
#define DATASIZE_AUX    64

#define LOCALITY_DEFAULT  0x1f
#define WR_LOCALITY_AUX   0x18

#endif    /* LCP_TBOOT_ONLY */






/*--------- LCP UUID ------------*/
#define LCP_POLICY_DATA_UUID   {0xab0d1925, 0xeee7, 0x48eb, 0xa9fc, \
                               {0xb, 0xac, 0x5a, 0x26, 0x2d, 0xe}}

/*--------- LCP FILE SIGNATURE ------------*/
#define LCP_POLICY_DATA_FILE_SIGNATURE   "Intel(R) TXT LCP_POLICY_DATA\0\0\0\0"

/*--------- Data structures of LCP Policy ------------*/
typedef tb_hash_t lcp_hash_t;

/*--------- LCP Policy Algorithm ------------*/
#define LCP_POLHALG_SHA1    TB_HALG_SHA1

/*--------- LCP Policy Type ------------*/
#define LCP_POLTYPE_LIST    0
#define LCP_POLTYPE_ANY     1

#define LCP_DEFAULT_POLICY_VERSION     0x0202
#define LCP_DEFAULT_POLICY_CONTROL     0x00

#define LCP_MAX_LISTS      8

typedef struct __packed {
    uint16_t    version;
    uint8_t     hash_alg;        /* one of LCP_POLHALG_* */
    uint8_t     policy_type;     /* one of LCP_POLTYPE_* */
    uint8_t     sinit_min_version;
    uint8_t     reserved1;
    uint16_t    data_revocation_counters[LCP_MAX_LISTS];
    uint32_t    policy_control;
    uint32_t    reserved2[2];
    lcp_hash_t  policy_hash;
} lcp_policy_t;

#define MAX_LCP_POLICY_SIZE        sizeof(lcp_policy_t)


#define LCP_POLSALG_NONE           0
#define LCP_POLSALG_RSA_PKCS_15    1

#define LCP_SIG_EXPONENT           65537

typedef struct __packed {
    uint16_t    revocation_counter;
    uint16_t    pubkey_size;
    uint8_t     pubkey_value[0];
    uint8_t     sig_block[];
} lcp_signature_t;

/* set bit 0: override PS policy for this element type */
#define DEFAULT_POL_ELT_CONTROL     0x0001

typedef struct __packed {
    uint32_t    size;
    uint32_t    type;
    uint32_t    policy_elt_control;
    uint8_t     data[];
} lcp_policy_element_t;

#define LCP_DEFAULT_POLICY_LIST_VERSION     0x0100

typedef struct __packed {
    uint16_t               version;
    uint8_t                reserved;
    uint8_t                sig_alg;
    uint32_t               policy_elements_size;
    lcp_policy_element_t   policy_elements[];
    /* optionally: */
    /* lcp_signature_t     sig; */
} lcp_policy_list_t;

#define LCP_FILE_SIG_LENGTH  32

typedef struct __packed {
    char               file_signature[LCP_FILE_SIG_LENGTH];
    uint8_t            reserved[3];
    uint8_t            num_lists;
    lcp_policy_list_t  policy_lists[];
} lcp_policy_data_t;

/*--------- LCP Element sub-types ------------*/

/* for clients that don't need non-custom elements */
#ifndef LCP_TBOOT_ONLY

#define LCP_POLELT_TYPE_MLE     0

typedef struct __packed {
    uint8_t      sinit_min_version;
    uint8_t      hash_alg;
    uint16_t     num_hashes;
    lcp_hash_t   hashes[];
} lcp_mle_element_t;



#define LCP_POLELT_TYPE_PCONF   1

typedef struct __packed {
    uint16_t    size_of_select;
    uint8_t     pcr_select[3];
} tpm_pcr_selection_t;

typedef uint8_t tpm_locality_selection_t;

#define TPM_DIGEST_SIZE          20
typedef struct __packed {
    uint8_t     digest[TPM_DIGEST_SIZE];
} tpm_digest_t;

typedef tpm_digest_t tpm_composite_hash_t;

typedef struct __packed {
    tpm_pcr_selection_t         pcr_selection;
    tpm_locality_selection_t    locality_at_release;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_short_t;

typedef struct __packed {
    uint16_t             num_pcr_infos;
    tpm_pcr_info_short_t pcr_infos[];
} lcp_pconf_element_t;



#define LCP_POLELT_TYPE_SBIOS   2

typedef struct __packed {
    uint8_t      hash_alg;
    uint8_t      reserved1[3];
    lcp_hash_t   fallback_hash;
    uint16_t     reserved2;
    uint16_t     num_hashes;
    lcp_hash_t   hashes[];
} lcp_sbios_element_t;

#endif    /* LCP_TBOOT_ONLY */



#define LCP_POLELT_TYPE_CUSTOM  3

typedef struct __packed {
    uuid_t       uuid;
    uint8_t      data[];
} lcp_custom_element_t;



#endif    /*  __TXT_LCP2_H__ */
