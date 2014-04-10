/*
 * lcputils.h: LCP utility fns
 *
 * Copyright (c) 2014, Intel Corporation
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

#ifndef __LCPUTILS_H__
#define __LCPUTILS_H__

#define MAJOR_VER(v)      ((v) >> 8)
#define MINOR_VER(v)      ((v) & 0xff)

#define ARRAY_SIZE(a)     (sizeof(a) / sizeof((a)[0]))

#define MAX_PATH           256

extern bool verbose;

extern void ERROR(const char *fmt, ...);
extern void LOG(const char *fmt, ...);
extern void DISPLAY(const char *fmt, ...);

extern size_t strlcpy(char *dst, const char *src, size_t siz);

extern void print_hex(const char *prefix, const void *data, size_t n);
extern void parse_comma_sep_ints(char *s, uint16_t ints[],
                                 unsigned int *nr_ints);

extern void *read_file(const char *file, size_t *length, bool fail_ok);
extern bool write_file(const char *file, const void *data, size_t size);

extern bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg);
extern bool parse_file(const char *filename,
		       bool (*parse_line)(const char *line));

extern const char *hash_alg_to_str(uint16_t alg);

extern const char *sig_alg_to_str(uint16_t alg);

extern uint16_t str_to_hash_alg(const char *str);

extern uint16_t str_to_sig_alg(const char *str, const uint16_t version);

extern size_t get_lcp_hash_size(uint16_t hash_alg);

extern bool verify_signature(const uint8_t *data, size_t data_size,
                             const uint8_t *pubkey, size_t pubkey_size,
                             const uint8_t *sig, bool is_sig_little_endian);

#endif    /* __LCPUTILS_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
