/*
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "../include/hash.h"
#include "uuid.h"
#include "tpm.h"


#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

void pcr_print(struct pcr *p, uint16_t alg)
{
	int i;

	if (!p) {
		return;
	}

	printf("log: \n");
	for (i = 0; i < p->log_idx; i++) {
		printf("[%02d] %03x: ",i, p->log[i].type);
		print_hash(&p->log[i].digest, alg);
	}
	printf("value: ");
	print_hash(&p->value, alg);
}

bool pcr_recalculate(struct pcr *p, uint16_t alg)
{
	int i;

	if (!p) {
		return false;
	}

	if (p->log_idx == 0)
		return true;

	memset(&p->value, 0, sizeof(tb_hash_t));

	for (i = 0; i < p->log_idx; i++) {
		struct pcr_event *e = &p->log[i];
		if (e->type == 0)
			continue;

		if (e->type == TPM_EVT_HASH_START) {
			if (extend_hash_start()) {
				memset(&p->value, 0, sizeof(tb_hash_t));
				if (!extend_hash(&p->value, &e->digest, alg))
					return false;
			} else {
				memcpy(&p->value, &e->digest, sizeof(tb_hash_t));
			}
		} else if (!extend_hash(&p->value, &e->digest, alg)) {
			return false;
		}
	}

	return true;
}

bool pcr_record_event(struct pcr *p, uint16_t alg, uint32_t type,
		      tb_hash_t *hash)
{
	struct pcr_event *evt;

	if (!p || !hash) {
		return false;
	}

	if (p->log_idx == MAX_LOG) {
		error_msg("PCR%d log is full!\n", p->num);
		return false;
	}

	if (type == TPM_EVT_HASH_START) {
		if (extend_hash_start()) {
			memset(&p->value, 0, sizeof(tb_hash_t));
			if (!extend_hash(&p->value, hash, alg)) {
				error_msg("failed to extend PCR%d with hash\n",
					p->num);
				return false;
			}

		} else {
			memcpy(&p->value, hash, sizeof(tb_hash_t));
		}
	} else if (!extend_hash(&p->value, hash, alg)) {
		error_msg("failed to extend PCR%d with hash\n", p->num);
		return false;
	}

	evt = &p->log[p->log_idx];
	evt->type = type;
	memcpy(&evt->digest, hash, sizeof(tb_hash_t));
	p->log_idx++;

	return true;
}

struct tpm *new_tpm(uint8_t version)
{
	int i, j, banks;
	struct tpm *t;

	switch (version) {
		case TPM12: banks = TPM12_BANKS;
			    break;
		case TPM20: banks = TPM20_BANKS;
			    break;
		default:
			    return NULL;
	}

	t = malloc(sizeof(*t));
	if (!t) {
		return NULL;
	}

	t->version = version;
	t->banks = malloc(banks * sizeof(struct pcr_bank));
	if (!t->banks) {
		free(t);
		return NULL;
	}

	for (i = 0; i < banks; i++) {
		for (j = 0; j < MAX_PCR; j++)
			t->banks[i].pcrs[j].num = j;
	}

	return t;
}

void destroy_tpm(struct tpm *t)
{
	free(t->banks);
	free(t);
}

bool tpm_record_event(struct tpm *t, uint16_t alg, void *e)
{
	int bnum = alg_to_bank(alg);
	struct pcr_bank *bank;
	struct pcr *p;
	uint32_t type;
	tb_hash_t *evt_hash;

	if (!t || !e) {
		return false;
	}

	bank = &t->banks[bnum];

	if (t->version == TPM12) {
		tpm12_pcr_event_t *event = e;

		if (event->pcr_index == 255)
			return true;

		if (event->pcr_index > 23)
			return false;

		p = &bank->pcrs[event->pcr_index];

		type = event->type;
		evt_hash = (tb_hash_t *) event->digest;
	} else {
		uint32_t pcr_num;

		pcr_num = *((uint32_t *) e);
		if (pcr_num > 23) {
			if (pcr_num == 255)
				return true;
			else
				return false;
		}

		p = &bank->pcrs[pcr_num];

		e += sizeof(uint32_t);
		type = *((uint32_t *) e);

		e += sizeof(uint32_t);
		evt_hash = (tb_hash_t *) e;
	}

	if (!pcr_record_event(p, alg, type, evt_hash))
		return false;

	t->active_banks |= alg_to_mask(alg);
	return true;
}

int tpm_count_event(struct tpm *t, uint16_t alg, uint32_t evt_type)
{
	int i, j, count = 0;
	struct pcr_bank *b;

	if (!t)
		return 0;

	b = tpm_get_bank(t, alg);
	if (!b)
		return 0;

	for (i = 0; i < MAX_PCR; i++) {
		struct pcr *p = &b->pcrs[i];

		for (j = 0; j < p->log_idx; j++) {
			if (p->log[j].type == evt_type)
				count++;
		}
	}

	return count;

}

struct pcr_event *tpm_find_event(struct tpm *t, uint16_t alg,
				uint32_t evt_type, int n)
{
	int i, j, count = 1;
	struct pcr_bank *b;

	if (!t)
		return NULL;

	b = tpm_get_bank(t, alg);
	if (!b)
		return NULL;

	for (i = 0; i < MAX_PCR; i++) {
		struct pcr *p = &b->pcrs[i];

		for (j = 0; j < p->log_idx; j++) {
			if (p->log[j].type == evt_type) {
				if (count == n)
					return &p->log[j];
				else
					count++;
			}
		}
	}

	return NULL;
}

bool tpm_substitute_event(struct tpm *t, uint16_t alg,
			  const struct pcr_event *evt)
{
	unsigned int i, j;
	struct pcr_bank *b;

	if (!t || !evt)
		return false;

	b = tpm_get_bank(t, alg);
	if (!b)
		return false;

	for (i = 0; i < MAX_PCR; ++i) {
		struct pcr *p = &b->pcrs[i];

		for (j = 0; j < p->log_idx; ++j) {
			if (p->log[j].type == evt->type) {
				p->log[j].digest = evt->digest;
			}
		}
	}

	return true;
}

bool tpm_clear_all_event(struct tpm *t, uint16_t alg, uint32_t evt_type)
{
	int i, j;
	struct pcr_bank *b;

	if (!t)
		return false;

	b = tpm_get_bank(t, alg);
	if (!b)
		return false;

	for (i = 0; i < MAX_PCR; i++) {
		struct pcr *p = &b->pcrs[i];

		for (j = 0; j < p->log_idx; j++) {
			if (p->log[j].type == evt_type)
				memset(&p->log[j], 0, sizeof(struct pcr_event));
		}
	}

	return true;
}

bool tpm_recalculate(struct tpm *t)
{
	int i,j;
	struct pcr_bank *b;

	if (!t) {
		return false;
	}

	for (i = 0; 1<<i < ALG_MASK_LAST; i++) {
		if (!(t->active_banks & 1<<i))
			continue;

		b = &t->banks[i];

		for (j=0; j<MAX_PCR; j++) {
			if (!pcr_recalculate(&b->pcrs[j], bank_to_alg(i)))
				return false;
		}
	}

	return true;
}

void tpm_print(struct tpm *t, uint16_t alg)
{
	int i,bnum = alg_to_bank(alg);
	struct pcr_bank *bank;
	tb_hash_t null_hash;

	if (!t) {
		return;
	}

	bank = &(t->banks[bnum]);

	memset(&null_hash, 0, sizeof(tb_hash_t));

	for (i = 0; i < MAX_PCR; i++) {
		if (memcmp(&(bank->pcrs[i].value),
		    &null_hash, sizeof(tb_hash_t)) == 0)
			continue;

		printf("%02d:",bank->pcrs[i].num);
		print_hash(&bank->pcrs[i].value, alg);
	}
}

void tpm_dump(struct tpm *t, uint16_t alg)
{
	int i,bnum = alg_to_bank(alg);
	struct pcr_bank *bank;
	tb_hash_t null_hash;

	if (!t) {
		return;
	}

	bank = &(t->banks[bnum]);

	memset(&null_hash, 0, sizeof(tb_hash_t));

	for (i = 0; i < MAX_PCR; i++) {
		if (memcmp(&bank->pcrs[i].value,
		    &null_hash, sizeof(tb_hash_t)) == 0)
			continue;

		pcr_print(&bank->pcrs[i], alg);
	}
}
