/*
 *
 * Copyright (c) 2015-2017 Daniel P. Smith
 * Copyright (c) 2017 Chris Rogers
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

#if HAVE_BZIP
#include <bzlib.h>
#endif

#define error_msg(fmt, ...)         fprintf(stderr, fmt, ##__VA_ARGS__)

#define BUFFER_SIZE 1024

#define NO_COMPRESSION 1
#define GZ_COMPRESSION 1<<1
#if HAVE_BZIP
#define BZ_COMPRESSION 1<<2
#endif


#if HAVE_BZIP
static bool read_bzip2(const char *path, FILE *dest_fd, size_t *len)
{
	FILE *fd;
	BZFILE *bzfd;
	char buf[BUFFER_SIZE];
	size_t bytes;
	int bzerror;

	*len = 0;
	if (!dest_fd)
		goto fail;

	fd = fopen(path, "r");
	if (!fd) {
		goto fail;
	}

	bzfd = BZ2_bzReadOpen(&bzerror, fd, 0, 0, NULL, 0 );
	if (bzerror != BZ_OK) {
		goto fail_bzfd;
	}

	bzerror = BZ_OK;
	while (bzerror == BZ_OK) {
		bytes = BZ2_bzRead(&bzerror, bzfd, buf, BUFFER_SIZE);
		if (bzerror == BZ_OK || bzerror == BZ_STREAM_END) {
			*len += bytes;
			if (fwrite(buf, 1, bytes, dest_fd) != bytes)
				goto fail_bzfd;
		} else {
			goto fail_bzfd;
		}
	}

	BZ2_bzReadClose(&bzerror, bzfd);
	fclose(fd);
	return true;

fail_bzfd:
	BZ2_bzReadClose(&bzerror, bzfd);
	fclose(fd);
fail:
	return false;
}
#endif

static bool read_gzip(const char *path, FILE *dest_fd, size_t *len)
{
	gzFile gzfd = NULL;
	char buf[BUFFER_SIZE];
	size_t bytes;

	*len = 0;

	gzfd = gzopen(path, "rb");
	if (!gzfd)
		goto fail;

	while (!gzeof(gzfd)) {
		bytes = gzread(gzfd, buf, BUFFER_SIZE);
		*len += bytes;
		if (fwrite(buf, 1, bytes, dest_fd) != bytes)
			goto fail_gz;
	}

	gzclose(gzfd);
	return true;

fail_gz:
	gzclose(gzfd);
fail:
	return false;
}

static bool read_module(const char *path, char **buffer, size_t *len, uint8_t flag)
{
	FILE *tmpfd = NULL;
	struct stat st;

	*len = 0;
	*buffer = NULL;

	if (stat(path, &st))
		goto fail;

	tmpfd = tmpfile();
	if (!tmpfd)
		goto fail;

	if ((flag & NO_COMPRESSION) || (flag & GZ_COMPRESSION)) {
		if (read_gzip(path, tmpfd, len) == false)
			goto fail_tmp;
#if HAVE_BZIP
	} else if (flag & BZ_COMPRESSION) {
		if (read_bzip2(path, tmpfd, len) == false)
			goto fail_tmp;
#endif
	} else {
		goto fail_tmp;
	}

	if (*len > 0)
		fseek(tmpfd, 0, SEEK_SET);
	else
		goto fail_tmp;

	*buffer = malloc(*len);
	if (*buffer == NULL)
		goto fail_tmp;
	memset(*buffer, 0, *len);

	if (fread(*buffer, 1, *len, tmpfd) != *len)
		goto fail_buf;

	fclose(tmpfd);
	return true;

fail_buf:
	free(*buffer);
fail_tmp:
	fclose(tmpfd);
fail:
	return false;
}

static bool hash_module(tb_hash_t *hash, const char* cmdline, const char *module,
	         size_t size, uint16_t hash_alg)
{
	tb_hash_t img_hash;

	if (cmdline == NULL)
		cmdline = "";

	if (module == NULL) {
		error_msg("passed an empty module for hashing\n");
		return false;
	}

	if (!hash_buffer((const unsigned char *)cmdline, strlen(cmdline), hash,
	      hash_alg)) {
		error_msg("failed to hash cmdline\n");
		return false;
	}

	/* hash image and extend into cmdline hash */
	if (!hash_buffer((const unsigned char *)module, size, &img_hash, hash_alg)) {
		error_msg("failed to hash module\n");
		return false;
	}
	if (!extend_hash(hash, &img_hash, hash_alg)) {
		error_msg("failed to extend cmdline hash with  module hash\n");
		return false;
	}

	return true;
}

static void print_sha256(tb_hash_t *hash)
{
	int i;

	if (hash == NULL)
		return;

	for (i = 0; i < SHA256_LENGTH; i++)
		printf("%02x", hash->sha256[i]);

	printf("\n");
}

static void print_sha1(tb_hash_t *hash)
{
	int i;

	if (hash == NULL)
		return;

	for (i = 0; i < SHA1_LENGTH; i++)
		printf("%02x", hash->sha1[i]);

	printf("\n");
}

static void print_hash_val(tb_hash_t *hash, uint16_t hash_alg)
{

	switch (hash_alg) {
		case TB_HALG_SHA1:
			print_sha1(hash);
			break;
		case TB_HALG_SHA256:
			print_sha256(hash);
			break;
		default:
			printf("Error: Unsupported hash algorithm\n");
			break;
	}
}

static bool read_hash(const char *hexstr, tb_hash_t *hash, uint16_t hash_alg)
{
	int len = strlen(hexstr);
	int i = 0, j = 0;
	int hash_length = 0;
	unsigned char *buf = NULL;

	switch (hash_alg) {
		case TB_HALG_SHA1:
			hash_length = SHA1_LENGTH;
			buf = (unsigned char *)hash->sha1;
			break;
		case TB_HALG_SHA256:
			hash_length = SHA256_LENGTH;
			buf = (unsigned char *)hash->sha256;
			break;
		default:
			hash_length = SHA1_LENGTH;
			buf = (unsigned char *)hash->sha1;
			break;
	}

	if (len == 1 && hexstr[0] == '0') {
		memset(buf, 0, hash_length);
		return true;
	}

	if (len/2 != hash_length)
		return false;

	if (len % 2 == 1) {
		if (sscanf(&(hexstr[0]), "%1hhx", &(buf[0])) != 1)
			return false;

		i = j = 1;
	}

	for (; i < len; i+=2, j++) {
		if (sscanf(&(hexstr[i]), "%2hhx", &(buf[j])) != 1)
			return false;
	}

	return true;
}

static void print_help(void)
{
	error_msg("module_hash [-hjz] [-e hash_str] -c cmd_line module_file\n"
		"\t-h Help: will print out this help message.\n"
		"\t-j module is compressed with BZip2\n"
		"\t-z module is compressed with GZip\n"
		"\t-e hash_str Extend Hash: has to be extended with module hash.\n"
		"\t-c cmd_line Command Line: the command line passed.\n"
		"\t-a hash algorithm to use.\n"
		"\tmodule_file: file name of module to hash.\n");
}

int main(int argc, char *argv[])
{
	extern int optind;
	int opt;
	size_t mod_len;
	char *module_path = NULL;
	char *cmdline = NULL;
	char *ext_str = NULL;
	char *mod_buf = NULL;
	uint16_t hash_alg = TB_HALG_SHA1;
	uint8_t flags = NO_COMPRESSION;
	tb_hash_t mod_hash, ext_hash;

	while ((opt = getopt(argc, (char ** const)argv, "he:c:a:jz")) != -1) {
		switch (opt) {
			case 'c':
				cmdline = malloc(strlen(optarg) + 1);
				if ( cmdline == NULL ) {
					printf("Out of memory\n");
					return 1;
				}
				strcpy(cmdline, optarg);
			break;
			case 'e':
				ext_str = malloc(strlen(optarg) + 1);
				if ( ext_str == NULL ) {
					printf("Out of memory\n");
					return 1;
				}
				strcpy(ext_str, optarg);
			break;
#ifdef HAVE_BZIP
			case 'j':
				if (flags & GZ_COMPRESSION) {
					print_help();
					error_msg("Error: -j cannot be used inconjunction with -z");
					return 1;
				} else {
					flags = BZ_COMPRESSION;
				}
			break;
#endif
			case 'z':
#ifdef HAVE_BZIP
				if (flags & BZ_COMPRESSION) {
					print_help();
					error_msg("Error: -z cannot be used inconjunction with -j");
					return 1;
				} else {
					flags = GZ_COMPRESSION;
				}
#else
				flags = GZ_COMPRESSION;
#endif
			break;
			case 'h':
				print_help();
				free(cmdline);
				return 1;
			case 'a':
				if (!strcmp(optarg, "sha1")) {
					hash_alg = TB_HALG_SHA1;
				} else if(!strcmp(optarg, "sha256")) {
					hash_alg = TB_HALG_SHA256;
				} else {
					hash_alg = TB_HALG_SHA1;
				}
			break;
			default:
			break;
		}
	}

	module_path = argv[optind];

	if(read_module(module_path, &mod_buf, &mod_len, flags) == false) {
		error_msg("failed to read in the module\n");
		goto fail;
	}

	if (hash_module(&mod_hash, cmdline, mod_buf, mod_len, hash_alg) == false) {
		error_msg("failed to hash the module\n");
		goto fail;
	}

	if (ext_str != NULL) {
		if (read_hash(ext_str, &ext_hash, hash_alg) == false) {
			error_msg("failed to pass valid hash to -e\n");
			goto fail;
		}
		if (extend_hash(&ext_hash, &mod_hash, hash_alg) == false) {
			error_msg("failed to extend hash\n");
			goto fail;
		}

		print_hash_val(&ext_hash, hash_alg);
	} else {
		print_hash_val(&mod_hash, hash_alg);
	}

	if (ext_str != NULL) free(ext_str);
	if (cmdline != NULL) free(cmdline);
	return 0;
fail:
	if (ext_str != NULL) free(ext_str);
	if (cmdline != NULL) free(cmdline);
	return 1;
}
