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
#include <stdint.h>
#include <stdbool.h>

#include "uuid.h"
#include "heap.h"
#include "tpm.h"


#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

struct tpm *parse_tpm12_log(char *buffer, size_t size)
{
	struct tpm *t;
	tpm12_pcr_event_t *c, *n;
	event_log_container_t *log = (event_log_container_t *) buffer;

	t = new_tpm(TPM12);
	if (!t){
		goto out;
	}
	/* TODO: check for signature */

	c = (tpm12_pcr_event_t *)((void*)log + log->pcr_events_offset);
	n = (tpm12_pcr_event_t *)((void*)log + log->next_event_offset);

	if ((char *) n > (buffer + size)){
		goto out_free;
	}

	while (c < n) {
		if (!tpm_record_event(t, TB_HALG_SHA1, (void *) c)) {
			goto out_free;
		}
		c = (void *)c + sizeof(*c) + c->data_size;
	}

	return t;
out_free:
	destroy_tpm(t);
out:
	return NULL;
}

struct tpm *parse_tpm20_log(char *buffer, size_t size)
{
	struct tpm *t;
	void *c, *n;
	uint32_t hash_size, data_size;
	heap_event_log_descr_t *log = (heap_event_log_descr_t *) buffer;

	t = new_tpm(TPM20);
	if (!t)
		goto out;

	hash_size = get_hash_size(log->alg);

	/* point at start of log */
	buffer += sizeof(heap_event_log_descr_t);
	c = buffer + log->pcr_events_offset;
	n = buffer + log->next_event_offset;

	if ((char *) n > (buffer + size))
		goto out_free;

	/* non-sha1 logs first entry is a no-op sha1 entry,
	 * so skip the first event
	 */
	if (log->alg != TB_HALG_SHA1){
		c += sizeof(tpm12_pcr_event_t) + sizeof(tpm20_log_descr_t);
	}

	while (c < n) {
		if (!tpm_record_event(t, log->alg, c))
			goto out_free;
		data_size = *(uint32_t *)(c + 2*sizeof(uint32_t) + hash_size);
		c += 3*sizeof(uint32_t) + hash_size + data_size;
	}

	return t;
out_free:
	destroy_tpm(t);
out:
	return NULL;
}
