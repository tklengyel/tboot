/*
 * pcr.h: pcr definitions
 *
 * Copyright (c) 2017 Daniel P. Smith
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

#ifndef __PCR_H__
#define __PCR_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "../include/config.h"
#include "../include/hash.h"
#include "heap.h"


#define TPM_EVT_HASH_START	0x402
#define TPM_EVT_MLE_HASH	0x404
#define TPM_EVT_TBOOT_HASH	0x501

struct pcr_event {
	uint32_t type;
	tb_hash_t digest;
};

#define MAX_PCR 24
#define MAX_LOG 50
struct pcr {
	uint8_t num;
	uint8_t log_idx;
	tb_hash_t value;
	struct pcr_event log[MAX_LOG];
};

#define SHA1_BANK 0
#define SHA256_BANK 1
#define SM3_BANK 2
#define SHA384_BANK 3
#define SHA512_BANK 4

struct pcr_bank {
	struct pcr pcrs[MAX_PCR];
};

#define TPM12 0x12
#define TPM20 0x20
#define TPM12_BANKS 1
#define TPM20_BANKS 5

struct tpm {
	uint8_t version;
	uint16_t alg;
	uint8_t num_banks;
	uint8_t active_banks;
	struct pcr_bank *banks;
};

static inline int alg_to_bank(uint16_t alg)
{
	if ( alg == TB_HALG_SHA1 )
		return SHA1_BANK;
	else if ( alg == TB_HALG_SHA256 )
		return SHA256_BANK;
	else if ( alg == TB_HALG_SM3 )
		return SM3_BANK;
	else if ( alg == TB_HALG_SHA384 )
		return SHA384_BANK;
	else if ( alg == TB_HALG_SHA512 )
		return SHA512_BANK;
	else
		return -1;
}

static inline int bank_to_alg(int bank)
{
	if ( bank == SHA1_BANK )
		return TB_HALG_SHA1 ;
	else if ( bank == SHA256_BANK )
		return TB_HALG_SHA256;
	else if ( bank == SM3_BANK )
		return TB_HALG_SM3 ;
	else if ( bank == SHA384_BANK )
		return TB_HALG_SHA384 ;
	else if ( bank == SHA512_BANK )
		return TB_HALG_SHA512;
	else
		return -1;
}

#define ALG_MASK_SHA1	1
#define ALG_MASK_SHA256 1<<1
#define ALG_MASK_SM3	1<<2
#define ALG_MASK_SHA384 1<<3
#define ALG_MASK_SHA512 1<<4
#define ALG_MASK_LAST	1<<5

static inline int alg_to_mask(uint16_t alg)
{
	if ( alg == TB_HALG_SHA1 )
		return ALG_MASK_SHA1;
	else if ( alg == TB_HALG_SHA256 )
		return ALG_MASK_SHA256;
	else if ( alg == TB_HALG_SM3 )
		return ALG_MASK_SM3;
	else if ( alg == TB_HALG_SHA384 )
		return ALG_MASK_SHA384;
	else if ( alg == TB_HALG_SHA512 )
		return ALG_MASK_SHA512;
	else
		return 0;
}

static inline struct pcr_bank *tpm_get_bank(const struct tpm *t, uint16_t alg)
{
	int bank;

	if (!t)
		return NULL;

	bank = alg_to_bank(alg);
	if (bank < 0)
		return NULL;

	if (!(t->active_banks & alg_to_mask(alg)))
		return NULL;

	return &t->banks[bank];
}

extern bool __hash_start_use_extend;
static inline void set_hash_start_extend(void)
{
	__hash_start_use_extend = true;
}

static inline bool extend_hash_start(void)
{
	return __hash_start_use_extend;
}

struct tpm *new_tpm(uint8_t version);
void destroy_tpm(struct tpm *t);
bool tpm_record_event(struct tpm *t, uint16_t alg, void *e);
int tpm_count_event(struct tpm *t, uint16_t alg, uint32_t evt_type);
struct pcr_event *tpm_find_event(struct tpm *t, uint16_t alg,
				uint32_t evt_type, int n);
bool tpm_substitute_event(struct tpm *t, uint16_t alg,
			  const struct pcr_event *evt);
bool tpm_clear_all_event(struct tpm *t, uint16_t alg, uint32_t evt_type);
bool tpm_recalculate(struct tpm *t);
void tpm_print(struct tpm *t, uint16_t alg);
void tpm_dump(struct tpm *t, uint16_t alg);
bool pcr_record_event(struct pcr *p, uint16_t alg, uint32_t type, tb_hash_t *hash);

#endif
