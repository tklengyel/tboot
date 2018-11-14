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
#include <getopt.h>
#include <zlib.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#include "../include/hash.h"
#include "uuid.h"
#include "tb_policy.h"
#include "tpm.h"
#include "util.h"
#include "eventlog.h"


/* flags */
#define FLAG_TPM12	1
#define FLAG_TPM20	1<<1
#define FLAG_DA		1<<2
#define FLAG_CURRENT	1<<3
#define FLAG_LOG	1<<4
#define FLAG_VERBOSE	1<<5

#define TPM12_LOG "/sys/kernel/security/txt/tpm12_binary_evtlog"
#define TPM20_LOG "/sys/kernel/security/txt/tpm20_binary_evtlog"

#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

bool __hash_start_use_extend = false;

static void print_help(void) {
	error_msg("pcr-calc [-h2dclvqe] [-a sha1|sha256] -p policy_file -m hash_str\n"
		"\t-h Help: will print out this help message.\n"
		"\t-2 TPM 2.0.\n"
		"\t-d D/A mode.\n"
		"\t-c Calculate from TPM eventlog.\n"
		"\t-l Print TPM eventlog.\n"
		"\t-v Print calculated TPM eventlog.\n"
		"\t-q Hash start quirk mode.\n"
		"\t-a alg Alogrithm: select what hash alogrithm to use.\n"
		"\t-p policy_file Tboot Policy: the policy that was/will be used.\n"
		"\t-m hash_str Multiboot Module: include module hash (MLE first).\n"
		"\t-e evt_type:hash_str Override PCR events type found in the logs with the provided value.\n");
}

static bool apply_lg_policy(struct tpm *t, tb_policy_t *policy, size_t pol_size,
			    tb_hash_t *mb, int mb_count,
			    const struct pcr_event *evt, int evt_count) {
	tb_hash_t *pol_hash;
	struct pcr *p;
	struct pcr_event *pe;
	int i, bnum, pnum;

	if (!tpm_clear_all_event(t, policy->hash_alg, TPM_EVT_TBOOT_HASH))
		goto out;

	pe = tpm_find_event(t, policy->hash_alg, TPM_EVT_MLE_HASH, 1);
	pe->digest = mb[0];

	for (i = 0; i < evt_count; ++i)
		if (!tpm_substitute_event(t, policy->hash_alg, &evt[i]))
			goto out;

	if (!tpm_recalculate(t))
		goto out;

	pol_hash = tb_policy_hash(policy, pol_size, policy->hash_alg);
	if (!pol_hash)
		goto out;

	bnum = alg_to_bank(policy->hash_alg);

	p = &t->banks[bnum].pcrs[17];
	if (!pcr_record_event(p, policy->hash_alg, TPM_EVT_TBOOT_HASH, pol_hash))
		goto out_pol;

	p = &t->banks[bnum].pcrs[18];
	if (!pcr_record_event(p, policy->hash_alg, TPM_EVT_TBOOT_HASH, &mb[1]))
		goto out_pol;

	for (i = 1; i < mb_count; i++) {
		tb_policy_entry_t *e = find_policy_entry(policy, i-1);

		pnum = (e == NULL) ? 18 : e->pcr;
		if (pnum == TB_POL_PCR_NONE)
			continue;

		p = &t->banks[bnum].pcrs[pnum];
		if (!pcr_record_event(p, policy->hash_alg,
		    TPM_EVT_TBOOT_HASH, &mb[i]))
			goto out_pol;
	}

	free(pol_hash);
	return true;

out_pol:
	free(pol_hash);
out:
	return false;
}

static bool apply_da_policy(struct tpm *t, tb_policy_t *policy, size_t pol_size,
			    tb_hash_t *mb, int mb_count,
			    const struct pcr_event *evt, int evt_count) {
	tb_hash_t *pol_hash;
	struct pcr *p;
	struct pcr_event *pe;
	int i, bnum, pnum;
	uint16_t hash_alg;

	hash_alg = t->alg == 0 ? policy->hash_alg : t->alg;

	if (!tpm_clear_all_event(t, hash_alg, TPM_EVT_TBOOT_HASH))
		goto out;

	pe = tpm_find_event(t, hash_alg, TPM_EVT_MLE_HASH, 1);
	pe->digest = mb[0];

	for (i = 0; i < evt_count; ++i)
		if (!tpm_substitute_event(t, hash_alg, &evt[i]))
			goto out;

	if (!tpm_recalculate(t))
		goto out;

	pol_hash = tb_policy_hash(policy, pol_size, hash_alg);
	if (!pol_hash)
		goto out;

	bnum = alg_to_bank(hash_alg);

	p = &t->banks[bnum].pcrs[17];
	if (!pcr_record_event(p, hash_alg, TPM_EVT_TBOOT_HASH, pol_hash))
		goto out_pol;

	p = &t->banks[bnum].pcrs[18];
	if (!pcr_record_event(p, hash_alg, TPM_EVT_TBOOT_HASH, pol_hash))
		goto out_pol;

	p = &t->banks[bnum].pcrs[17];
	if (!pcr_record_event(p, hash_alg, TPM_EVT_TBOOT_HASH, &mb[1]))
		goto out_pol;

	for (i = 1; i < mb_count; i++) {
		tb_policy_entry_t *e = find_policy_entry(policy, i - 1);

		pnum = (e == NULL) ? 17 : e->pcr;
		if (pnum == TB_POL_PCR_NONE)
			continue;

		p = &t->banks[bnum].pcrs[pnum];
		if (!pcr_record_event(p, hash_alg,
		    TPM_EVT_TBOOT_HASH, &mb[i]))
			goto out_pol;
	}

	free(pol_hash);
	return true;

out_pol:
	free(pol_hash);
out:
	return false;
}

int main(int argc, char *argv[]) {
	extern int optind;
	int opt, flags, mb_count = 0, evt_count = 0, ret = 0;
	tb_hash_t mb[20];
	struct pcr_event evt[20];
	struct tpm *t = NULL;
	uint16_t alg_override = 0;
	size_t pol_size = 0;
	tb_policy_t *policy_file = NULL;

	flags = FLAG_TPM12;

	while ((opt = getopt(argc, (char ** const)argv, "h2dclvqa:p:m:e:")) != -1) {
		switch (opt) {
			case 'm':
				if (mb_count >= 20) {
					error_msg("passed max number of hashes to -m\n");
					ret = 1;
					goto out;
				}
				if (read_hash(optarg, &mb[mb_count]) == false) {
					error_msg("failed to pass valid hash to -m\n");
					ret = 1;
					goto out;
				}
				mb_count++;
			break;
			case 'p':
				pol_size = read_file((char *) optarg,
						     (char **) &policy_file);
				if ( pol_size == 0 ) {
					error_msg("failed to read in policy file\n");
					ret = 1;
					goto out;
				}
			break;
			case 'a':
				if (strcmp(optarg, "sha1") == 0) {
					alg_override = TB_HALG_SHA1;
				} else if (strcmp(optarg, "sha256") == 0) {
					alg_override = TB_HALG_SHA256;
				} else {
					error_msg("unsupported hash algorithm\n");
					ret = 1;
					goto out;
				}

			break;
			case '2':
				flags &= ~FLAG_TPM12;
				flags |= FLAG_TPM20;
				flags |= FLAG_DA;
			break;
			case 'd':
				flags |= FLAG_DA;
			break;
			case 'c':
				flags |= FLAG_CURRENT;
			break;
			case 'l':
				flags |= FLAG_LOG;
			break;
			case 'v':
				flags |= FLAG_VERBOSE;
			break;
			case 'q':
				set_hash_start_extend();
			break;
			case 'e':
				if (evt_count >= 20) {
					error_msg("passed max number of pcr events to -e\n");
					ret = 1;
					goto out;
				}
				if (read_pcr_event(optarg, &evt[evt_count]) <= 0) {
					error_msg("failed to pass valid pcr event to -e\n");
					ret = 1;
					goto out;
				}
				++evt_count;
			break;
			case 'h':
				print_help();
				ret = 1;
				goto out;
			default:
			break;
		}
	}
	if (!policy_file) {
		if (!(flags & FLAG_CURRENT) && !(flags & FLAG_LOG)) {
			error_msg("the policy file must be provided!\n");
			ret = 1;
			goto out;
		} else if (alg_override == 0) {
			error_msg("an hash algorithm must be provided!\n");
			ret = 1;
			goto out;
		}
	}

	if (flags & FLAG_TPM12) {
		char *buffer;
		size_t size = read_file(TPM12_LOG, &buffer);

		if (size > 0) {
			t = parse_tpm12_log(buffer, size);
			free(buffer);
		}

		if (!t) {
			error_msg("failed to parse TPM 1.2 event log.\n");
			ret = 1;
			goto out;
		}

		t->alg = TB_HALG_SHA1;
	} else {
		char *buffer;
		size_t size = read_file(TPM20_LOG, &buffer);

		if (size > 0) {
			t = parse_tpm20_log(buffer, size);
			free(buffer);
		}

		if (!t) {
			error_msg("failed to parse TPM 2.0 event log.\n");
			ret = 1;
			goto out;
		}

// broken as you need to override if there is no policy file, fix!!!
		t->alg = alg_override != 0 ? alg_override : policy_file->hash_alg;
	}

	if (flags & FLAG_CURRENT) {
		tpm_print(t, t->alg);
		return 0;
	}

	if (flags & FLAG_LOG) {
		tpm_dump(t, t->alg);
		return 0;
	}

	if (flags & FLAG_DA) {
		if (!apply_da_policy(t, policy_file, pol_size, mb, mb_count, evt, evt_count)) {
			error_msg("failed applying DA policy.\n");
			ret = 1;
			goto out_destroy;
		}
	} else {
		if (!apply_lg_policy(t, policy_file, pol_size, mb, mb_count, evt, evt_count)) {
			error_msg("failed applying LG policy.\n");
			ret = 1;
			goto out_destroy;
		}
	}

	if (flags & FLAG_VERBOSE)
		tpm_dump(t, t->alg);
	else
		tpm_print(t, t->alg);

	return 0;

out_destroy:
	destroy_tpm(t);
out:
	return ret;
}
