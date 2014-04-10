/*
 * Copyright 2014 Intel Corporation. All Rights Reserved.
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

#ifndef __LCP_H__
#define __LCP_H__

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

/*
 * Version = 3.0 - new version format of LCP Policy. Major version
 * is incremented since layout is incompatible with previous revision.
 */

/*--------- LCP UUID ------------*/
#define LCP_POLICY_DATA_UUID   {0xab0d1925, 0xeee7, 0x48eb, 0xa9fc, \
                               {0xb, 0xac, 0x5a, 0x26, 0x2d, 0xe}}

/*--------- CUSTOM ELT UUID ------------*/
#define LCP_CUSTOM_ELEMENT_TBOOT_UUID {0xc3930641, 0xe3cb, 0x4f40, 0x91d7, \
                                      {0x27, 0xf8, 0xb9, 0xe2, 0x5c, 0x86}}

/*--------- LCP FILE SIGNATURE ------------*/
#define LCP_POLICY_DATA_FILE_SIGNATURE   "Intel(R) TXT LCP_POLICY_DATA\0\0\0\0"

/*--------- LCP Policy Type ------------*/
#define LCP_POLTYPE_LIST    0
#define LCP_POLTYPE_ANY     1


#define LCP_DEFAULT_POLICY_VERSION     0x0300
#define LCP_DEFAULT_POLICY_CONTROL     0x00

#define LCP_MAX_LISTS      8


/*--------- with LCP_POLICY version 2.0 ------------*/
#define SHA1_LENGTH        20
#define SHA256_LENGTH      32

typedef union {
    uint8_t    sha1[SHA1_LENGTH];
    uint8_t    sha256[SHA256_LENGTH];
} lcp_hash_t;

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

#define LCP_POLELT_TYPE_CUSTOM  3
typedef struct __packed {
    uuid_t       uuid;
    uint8_t      data[];
} lcp_custom_element_t;

#define LCP_DEFAULT_POLICY_LIST_VERSION     0x0200
#define LCP_TPM12_POLICY_LIST_VERSION       0x0100
#define LCP_TPM20_POLICY_LIST_VERSION       0x0200
typedef struct __packed {
    uint16_t               version; /* = 1.0 */
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

#define LCP_DEFAULT_POLICY_VERSION_2   0x0202
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


/*--------- LCP_POLICY version 3.0 ------------*/
#define TPM_ALG_SHA1	0x0004
#define TPM_ALG_SHA256	0x000B
#define TPM_ALG_SHA384	0x000C
#define TPM_ALG_SHA512	0x000D
#define TPM_ALG_NULL	0x0010
#define TPM_ALG_SM3_256	0x0012

#define TPM_ALG_RSASSA  0x0014
#define TPM_ALG_ECDSA   0x0018
#define TPM_ALG_SM2     0x001B

#define SHA1_DIGEST_SIZE 	20
#define SHA256_DIGEST_SIZE	32
#define SHA384_DIGEST_SIZE	48
#define SHA512_DIGEST_SIZE	64
#define SM3_256_DIGEST_SIZE	32

typedef union {
    uint8_t    sha1[SHA1_DIGEST_SIZE];
    uint8_t    sha256[SHA256_DIGEST_SIZE];
    uint8_t    sha384[SHA384_DIGEST_SIZE];
    uint8_t    sha512[SHA512_DIGEST_SIZE];
    uint8_t    sm3[SM3_256_DIGEST_SIZE];
} lcp_hash_t2;

typedef struct __packed {
    uint16_t    hash_alg;
    uint8_t     size_of_select;
    uint8_t     pcr_select[];
} tpms_pcr_selection_t;

typedef struct __packed {
    uint32_t              count;
    tpms_pcr_selection_t  pcr_selections;
} tpml_pcr_selection_t;

typedef struct __packed {
    uint16_t    size;
    uint8_t     buffer[];
} tpm2b_digest_t;

typedef struct __packed {
    tpml_pcr_selection_t    pcr_selection;
    tpm2b_digest_t          pcr_digest;
} tpms_quote_info_t;

#define LCP_POLELT_TYPE_MLE2       0x10
typedef struct __packed {
    uint8_t      sinit_min_version;
    uint8_t      reserved;
    uint16_t     hash_alg;
    uint16_t     num_hashes;
    lcp_hash_t2  hashes[];
} lcp_mle_element_t2;

#define LCP_POLELT_TYPE_PCONF2     0x11
typedef struct __packed {
    uint16_t             hash_alg;
    uint16_t             num_pcr_infos;
    tpms_quote_info_t    prc_infos[];
} lcp_pconf_element_t2;

#define LCP_POLELT_TYPE_SBIOS2     0x12
typedef struct __packed {
    uint16_t     hash_alg;
    uint8_t      reserved1[2];
    lcp_hash_t2  fallback_hash;
    uint16_t     reserved2;
    uint16_t     num_hashes;
    lcp_hash_t2  hashes[];
} lcp_sbios_element_t2;

#define LCP_POLELT_TYPE_CUSTOM2    0x13
typedef struct __packed {
    uuid_t       uuid;
    uint8_t      data[];
} lcp_custom_element_t2;

#define LCP_POLELT_TYPE_STM2       0x14
typedef struct __packed {
    uint16_t       hash_alg;
    uint16_t       num_hashes;
    lcp_hash_t2    hashes[];
} lcp_stm_element_t2;

typedef struct __packed {
    uint16_t   version;         /* = 3.0 */
    uint16_t   hash_alg;        /* one of LCP_POLHALG_* */
    uint8_t    policy_type;     /* one of LCP_POLTYPE_* */
    uint8_t    sinit_min_version;
    uint16_t   data_revocation_counters[LCP_MAX_LISTS];
    uint32_t   policy_control;
    uint8_t    max_sinit_min_ver;  /* Defined for PO only. Reserved for PS */
    uint8_t    max_biosac_min_ver; /* Defined for PO only. Reserved for PS */
    uint16_t   lcp_hash_alg_mask;  /* Mask of approved algorithms for LCP evaluation */
    uint32_t   lcp_sign_alg_mask;  /* Mask of approved signature algorithms for LCP evaluation */
    uint16_t   aux_hash_alg_mask;  /* Approved algorithm for auto - promotion hash */
    uint16_t   reserved2;
    lcp_hash_t2    policy_hash;
} lcp_policy_t2;

typedef struct __packed {
    uint16_t    revocation_counter;
    uint16_t    pubkey_size;
    uint8_t     pubkey_value[0];
    uint8_t     sig_block[];
} lcp_rsa_signature_t;

typedef struct __packed {
    uint16_t    revocation_counter;
    uint16_t    pubkey_size;
    uint32_t    reserved;
    uint8_t     qx[0];
    uint8_t     qy[0];
    uint8_t     r[0];
    uint8_t     s[0];
} lcp_ecc_signature_t;

typedef union   __packed {
    lcp_rsa_signature_t     rsa_signature;
    lcp_ecc_signature_t     ecc_signature;
} lcp_signature_t2;

typedef struct __packed {
    uint16_t               version; /* = 2.0 */
    uint16_t               sig_alg;
    uint32_t               policy_elements_size;
    lcp_policy_element_t   policy_elements[];
//#if (sig_alg != TPM_ALG_NULL)
//    lcp_signature_t        sig;
//#endif
} lcp_policy_list_t2;

typedef union  __packed {
    lcp_policy_list_t   tpm12_policy_list;
    lcp_policy_list_t2  tpm20_policy_list;
} lcp_list_t; 

typedef struct __packed {
    char          file_signature[32];
    uint8_t       reserved[3];
    uint8_t       num_lists;
    lcp_list_t    policy_lists[];
} lcp_policy_data_t2;

#endif    /*  __LCP_H__ */
