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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "../include/hash.h"
#include "uuid.h"
#include "tpm.h"

#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

bool read_hash(const char *hexstr, tb_hash_t *hash)
{
	size_t len = strlen(hexstr);
	int i, j;
	unsigned char *buf = (unsigned char *)hash;

	if (len == 1 && hexstr[0] == '0') {
		memset(hash, 0, sizeof(tb_hash_t));
		return true;
	}

	if (len / 2 >= sizeof(tb_hash_t))
		return false;
	if (len % 2 == 1)
		return false;

	for (i=0, j=0; i < (int) len; i+=2, j++) {
		if (sscanf(&(hexstr[i]), "%2hhx", &(buf[j])) != 1)
			return false;
	}

	return true;
}

#define BLOCK_SIZE 1024
size_t read_file(const char *path, char **buffer)
{
	char *top, *insert;
	int fd, count;
	size_t allocated = 0, total = 0;

	if (access(path, F_OK) == -1) {
		error_msg("no access to file: %s\n",path);
		goto out;
	}

	allocated += 4*BLOCK_SIZE;
	*buffer = (char *) malloc(allocated);
	if (!*buffer) {
		error_msg("unable to allocate memory\n");
		goto out;
	}

	top = *buffer;
	insert = *buffer;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		error_msg("unable to open file: %s\n",path);
		goto out_free;
	}

	while ((count = read(fd, insert, BLOCK_SIZE)) != 0) {
		if (count == -1) {
			error_msg("read failed\n");
			goto out_fd;
		}

		total += count;
		insert += count;

		if ((total + BLOCK_SIZE) > allocated) {
			allocated += BLOCK_SIZE;
			*buffer = realloc(*buffer, allocated);
			if (! *buffer) {
				error_msg("failed to resize buffer\n");
				/* reset buffer to free original */
				*buffer = top;
				goto out_fd;
			}
			top = *buffer;
			insert = top + total;
		}
	}

	close(fd);
	return total;

out_fd:
	close(fd);
out_free:
	free(*buffer);
out:
	return 0;
}

/*
 * Parse a string representing a pcr event.
 * Format: <event-id>:<hash>
 * e.g, for sha256: '0x40f:5a3e80a37915b1601c363acd1601df7ef257d5d32c664004a2ec0484a4f60628'
 * e.g, for sha512: '0x40f:be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09
 */
#define PCREVT_BUF_LEN 135
int read_pcr_event(const char *s, struct pcr_event *evt)
{
	size_t len = strnlen(s, PCREVT_BUF_LEN);
	char *end = NULL;
	unsigned long type;
	tb_hash_t digest;

	if (len >= PCREVT_BUF_LEN)
		return -1;

	type = strtoul(s, &end, 0);
	if (type == ULONG_MAX)
		return -1;
	if (!end || *end != ':' || s == end)
		return -1;

	if (!read_hash(&end[1], &digest))
		return -1;

	evt->type = type;
	evt->digest = digest;
	return len;
}
