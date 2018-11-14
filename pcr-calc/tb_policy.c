/*
 * Copyright (c) 2015-2017, Daniel P. Smith
 * Copyright (c) 2006-2008, Intel Corporation
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "uuid.h"
#include "../include/hash.h"
#include "../include/tb_policy.h"

tb_hash_t *tb_policy_hash(tb_policy_t *pol, size_t size, uint16_t alg)
{
	tb_hash_t *hash;
	uint8_t buf[sizeof(pol->policy_control) + sizeof(tb_hash_t)];
	uint32_t hash_size = get_hash_size(alg);

	if (pol == NULL)
		goto out;

	hash = (tb_hash_t *) malloc(sizeof(tb_hash_t));
	if (!hash)
		goto out;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, &pol->policy_control, sizeof(pol->policy_control));

	if ( pol->policy_control & TB_POLCTL_EXTEND_PCR17 )
		if ( !hash_buffer((unsigned char *)pol, size,
                     (tb_hash_t *)&buf[sizeof(pol->policy_control)],
		     alg))
			goto out_free;

	if ( !hash_buffer(buf, hash_size + sizeof(pol->policy_control),
	     hash, alg) )
		goto out_free;

	return hash;
out_free:
	free(hash);
out:
	return NULL;
}
