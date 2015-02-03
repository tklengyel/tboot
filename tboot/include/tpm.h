/*
 * tpm.h: TPM-related support functions
 *
 * Copyright (c) 2006-2009, Intel Corporation
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

#ifndef __TPM_H__
#define __TPM_H__

#include <types.h>
#include <io.h>
#include <hash.h>
#include <integrity.h>

/* un-comment to enable detailed command tracing */
//#define TPM_TRACE

#define TPM_LOCALITY_BASE             0xfed40000
#define TPM_LOCALITY_0                TPM_LOCALITY_BASE
#define TPM_LOCALITY_1                (TPM_LOCALITY_BASE | 0x1000)
#define TPM_LOCALITY_2                (TPM_LOCALITY_BASE | 0x2000)
#define TPM_LOCALITY_3                (TPM_LOCALITY_BASE | 0x3000)
#define TPM_LOCALITY_4                (TPM_LOCALITY_BASE | 0x4000)
#define TPM_LOCALITY_BASE_N(n)        (TPM_LOCALITY_BASE | ((n) << 12))
#define TPM_NR_LOCALITIES             5
#define NR_TPM_LOCALITY_PAGES         ((TPM_LOCALITY_1 - TPM_LOCALITY_0) >> \
                                       PAGE_SHIFT)

/*
 * Command Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      | COMMAND CODE  |    other ...
 *       -------------------------------------------------------------
 *
 * Response Header Fields:
 *       0   1   2   3   4   5   6   7   8   9   10  ...
 *       -------------------------------------------------------------
 *       | TAG  |     SIZE      |  RETURN CODE  |    other ...
 *       -------------------------------------------------------------
 */
#define CMD_HEAD_SIZE           10
#define RSP_HEAD_SIZE           10
#define CMD_SIZE_OFFSET         2
#define CMD_CC_OFFSET           6
#define RSP_SIZE_OFFSET         2
#define RSP_RST_OFFSET          6

/*
 * The term timeout applies to timings between various states
 * or transitions within the interface protocol.
 */
#define TIMEOUT_UNIT    (0x100000 / 330) /* ~1ms, 1 tpm r/w need > 330ns */
#define TIMEOUT_A       750  /* 750ms */
#define TIMEOUT_B       2000 /* 2s */
#define TIMEOUT_C       75000  /* 750ms */
#define TIMEOUT_D       750  /* 750ms */

typedef struct __packed {
    uint32_t timeout_a;
    uint32_t timeout_b;
    uint32_t timeout_c;
    uint32_t timeout_d;
} tpm_timeout_t;

/*
 * The TCG maintains a registry of all algorithms that have an
 * assigned algorithm ID. That registry is the definitive list
 * of algorithms that may be supported by a TPM.
 */
#define TPM_ALG_ERROR             0x0000
#define TPM_ALG_FIRST             0x0001
#define TPM_ALG_RSA               0x0001
#define TPM_ALG_DES               0x0002
#define TPM_ALG__3DES             0x0003
#define TPM_ALG_SHA               0x0004
#define TPM_ALG_SHA1              0x0004
#define TPM_ALG_HMAC              0x0005
#define TPM_ALG_AES               0x0006
#define TPM_ALG_MGF1              0x0007
#define TPM_ALG_KEYEDHASH         0x0008
#define TPM_ALG_XOR               0x000A
#define TPM_ALG_SHA256            0x000B
#define TPM_ALG_SHA384            0x000C
#define TPM_ALG_SHA512            0x000D
#define TPM_ALG_WHIRLPOOL512      0x000E
#define TPM_ALG_NULL              0x0010
#define TPM_ALG_SM3_256           0x0012
#define TPM_ALG_SM4               0x0013
#define TPM_ALG_RSASSA            0x0014
#define TPM_ALG_RSAES             0x0015
#define TPM_ALG_RSAPSS            0x0016
#define TPM_ALG_OAEP              0x0017
#define TPM_ALG_ECDSA             0x0018
#define TPM_ALG_ECDH              0x0019
#define TPM_ALG_ECDAA             0x001A
#define TPM_ALG_SM2               0x001B
#define TPM_ALG_ECSCHNORR         0x001C
#define TPM_ALG_KDF1_SP800_56a    0x0020
#define TPM_ALG_KDF2              0x0021
#define TPM_ALG_KDF1_SP800_108    0x0022
#define TPM_ALG_ECC               0x0023
#define TPM_ALG_SYMCIPHER         0x0025
#define TPM_ALG_CTR               0x0040
#define TPM_ALG_OFB               0x0041
#define TPM_ALG_CBC               0x0042
#define TPM_ALG_CFB               0x0043
#define TPM_ALG_ECB               0x0044
#define TPM_ALG_LAST              0x0044
#define TPM_ALG_MAX_NUM           (TPM_ALG_LAST - TPM_ALG_ERROR)


/*
 * assumes that all reg types follow above format:
 *   - packed
 *   - member named '_raw' which is array whose size is that of data to read
 */
#define read_tpm_reg(locality, reg, pdata)      \
    _read_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

#define write_tpm_reg(locality, reg, pdata)     \
    _write_tpm_reg(locality, reg, (pdata)->_raw, sizeof(*(pdata)))

static inline void _read_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for ( size_t i = 0; i < size; i++ )
        _raw[i] = readb((TPM_LOCALITY_BASE_N(locality) | reg) + i);
}

static inline void _write_tpm_reg(int locality, u32 reg, u8 *_raw, size_t size)
{
    for ( size_t i = 0; i < size; i++ )
        writeb((TPM_LOCALITY_BASE_N(locality) | reg) + i, _raw[i]);
}

/*
 * the following inline function reversely copy the bytes from 'in' to
 * 'out', the byte number to copy is given in count.
 */
#define reverse_copy(out, in, count) \
    _reverse_copy((uint8_t *)(out), (uint8_t *)(in), count)

static inline void _reverse_copy(uint8_t *out, uint8_t *in, uint32_t count)
{
    for ( uint32_t i = 0; i < count; i++ )
        out[i] = in[count - i - 1];
}

/* alg id list supported by Tboot */
extern u16 tboot_alg_list[];

typedef tb_hash_t tpm_digest_t;
typedef tpm_digest_t tpm_pcr_value_t;

/* only for tpm1.2 to (un)seal */
extern tpm_pcr_value_t post_launch_pcr17;
extern tpm_pcr_value_t post_launch_pcr18;

struct tpm_if;

struct tpm_if {
#define TPM12_VER_MAJOR   1
#define TPM12_VER_MINOR   2
#define TPM20_VER_MAJOR   2
#define TPM20_VER_MINOR   0
    u8 major;
    u8 minor;
    u16 family;

    tpm_timeout_t timeout;

    u32 error; /* last reported error */
    u32 cur_loc;

    u16 banks;
    u16 algs_banks[TPM_ALG_MAX_NUM];
    u16 alg_count;
    u16 algs[TPM_ALG_MAX_NUM];

    /*
     * Only for version>=2. PCR extend policy.
     */
#define TB_EXTPOL_AGILE         0
#define TB_EXTPOL_EMBEDDED      1
#define TB_EXTPOL_FIXED         2
    u8 extpol;
    u16 cur_alg;

    /* NV index to be used */
    u32 lcp_own_index;
    u32 tb_policy_index;
    u32 tb_err_index;
    u32 sgx_svn_index;

    bool (*init)(struct tpm_if *ti);

    bool (*pcr_read)(struct tpm_if *ti, u32 locality, u32 pcr,
            tpm_pcr_value_t *out);
    bool (*pcr_extend)(struct tpm_if *ti, u32 locality, u32 pcr,
            const hash_list_t *in);
    bool (*pcr_reset)(struct tpm_if *ti, u32 locality, u32 pcr);
    bool (*hash)(struct tpm_if *ti, u32 locality, const u8 *data,
            u32 data_size, hash_list_t *hl);

    bool (*nv_read)(struct tpm_if *ti, u32 locality, u32 index,
            u32 offset, u8 *data, u32 *data_size);
    bool (*nv_write)(struct tpm_if *ti, u32 locality, u32 index,
            u32 offset, const u8 *data, u32 data_size);
    bool (*get_nvindex_size)(struct tpm_if *ti, u32 locality,
            u32 index, u32 *size);

#define TPM_NV_PER_WRITE_STCLEAR  (1<<14) 
#define TPM_NV_PER_WRITEDEFINE    (1<<13)
#define TPM_NV_PER_WRITEALL       (1<<12)
#define TPM_NV_PER_AUTHWRITE      (1<<2)
#define TPM_NV_PER_OWNERWRITE     (1<<1)
#define TPM_NV_PER_PPWRITE        (1<<0)
    bool (*get_nvindex_permission)(struct tpm_if *ti, u32 locality,
            u32 index, u32 *attribute);

    bool (*seal)(struct tpm_if *ti, u32 locality, u32 in_data_size,
            const u8 *in_data, u32 *sealed_data_size, u8 *sealed_data);
    bool (*unseal)(struct tpm_if *ti, u32 locality, u32 sealed_data_size,
            const u8 *sealed_data, u32 *secret_size, u8 *secret);
    bool (*verify_creation)(struct tpm_if *ti, u32 sealed_data_size,
            u8 *sealed_data);

    bool (*get_random)(struct tpm_if *ti, u32 locality,
            u8 *random_data, u32 *data_size);

    uint32_t (*save_state)(struct tpm_if *ti, u32 locality);

    bool (*cap_pcrs)(struct tpm_if *ti, u32 locality, int pcr);
    bool (*check)(void);
};

extern struct tpm_if tpm_12_if;
extern struct tpm_if tpm_20_if;
extern struct tpm_if *g_tpm;

extern bool tpm_validate_locality(uint32_t locality);
extern bool release_locality(uint32_t locality);
extern bool prepare_tpm(void);
extern bool tpm_detect(void);
extern void tpm_print(struct tpm_if *ti);
extern bool tpm_submit_cmd(u32 locality, u8 *in, u32 in_size,
        u8 *out, u32 *out_size);


//#define TPM_UNIT_TEST 1

#ifdef TPM_UNIT_TEST
void tpm_unit_test(void);
#else
#define tpm_unit_test()
#endif   /* TPM_UNIT_TEST */


#endif   /* __TPM_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
