/*
 * lcputils2.c: misc. LCP helper fns
 *
 * Copyright (c) 2009, Intel Corporation
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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "polelt_plugin.h"
#include "lcputils2.h"

void ERROR(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void LOG(const char *fmt, ...)
{
    va_list ap;

    if ( verbose ) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

void DISPLAY(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    strncpy(dst, src, siz-1);
    if ( siz != 0 )
        *(dst + siz-1) = '\0';
    return strlen(src);
}

void print_hex(const char *prefix, const void *data, size_t n)
{
#define NUM_CHARS_PER_LINE    20
    unsigned int i = 0;
    while ( i < n ) {
        if ( i % NUM_CHARS_PER_LINE == 0 && prefix != NULL )
            DISPLAY("%s", prefix);
		DISPLAY("%02x ", *(uint8_t *)data++);
        i++;
        if ( i % NUM_CHARS_PER_LINE == 0 )
            DISPLAY("\n");
    }
    if ( i % NUM_CHARS_PER_LINE != 0 )
        DISPLAY("\n");
}

void parse_comma_sep_ints(char *s, uint16_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;

    while ( true ) {
        char *str = strsep(&s, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    if ( nr == *nr_ints )
        ERROR("Error: too many items in list\n");
    *nr_ints = nr;
    return;
}

void *read_file(const char *file, size_t *length, bool fail_ok)
{
    FILE *fp = fopen(file, "rb");
    if ( fp == NULL ) {
        if ( !fail_ok )
            ERROR("Error: failed to open file %s: %s\n", file,
                  strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        ERROR("Error: failed to allocate %d bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        ERROR("Error: reading file %s\n", file);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    return data;
}

bool write_file(const char *file, const void *data, size_t size)
{
    FILE *fp = fopen(file, "wb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s for writing: %s\n",
              file, strerror(errno));
        return false;
    }
    if ( fwrite(data, size, 1, fp) != 1 ) {
        ERROR("Error: writing file %s\n", file);
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

bool parse_line_hashes(const char *line, tb_hash_t *hash)
{
    /* skip any leading whitespace */
    while ( *line != '\0' && isspace(*line) )
        line++;

    /* rest of line is hex of hash */
    unsigned int i = 0;
    while ( *line != '\0' && *line != '\n' ) {
        char *next;
        hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
        if ( next == line )      /* done */
            break;
        line = next;
        /* spaces at end cause strtoul() to interpret as 0, so skip them */
        while ( *line != '\0' && !isxdigit(*line) )
            line++;
    }
    if ( i != get_hash_size(TB_HALG_SHA1_LG) ) {
        ERROR("Error: incorrect number of chars for hash\n");
        return false;
    }

    return true;
}

bool parse_file(const char *filename, bool (*parse_line)(const char *line))
{
    if ( filename == NULL || parse_line == NULL )
        return false;

    LOG("reading hashes file %s...\n", filename);

    FILE *fp = fopen(filename, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s (%s)\n", filename, strerror(errno));
        return false;
    }

    static char line[128];
    while ( true ) {
        char *s = fgets(line, sizeof(line), fp);

        if ( s == NULL ) {
            fclose(fp);
            return true;
        }

        LOG("read line: %s", line);

        if ( !(*parse_line)(line) ) {
            fclose(fp);
            return false;
        }
    }

    fclose(fp);
    return false;
}

const char *hash_alg_to_str(uint8_t alg)
{
    static const char *alg_str[] = { "LCP_POLHALG_SHA1" };
    static char buf[32];

    if ( alg > ARRAY_SIZE(alg_str) ) {
        snprintf(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
    else
        return alg_str[alg];
}

size_t get_lcp_hash_size(uint8_t hash_alg)
{
    if ( hash_alg != LCP_POLHALG_SHA1 )
        return 0;
    return SHA1_LENGTH;
}

bool verify_signature(const uint8_t *data, size_t data_size,
                      const uint8_t *pubkey, size_t pubkey_size,
                      const uint8_t *sig, bool is_sig_little_endian)
{
    unsigned int i;

    /* policy key is little-endian and openssl wants big-endian, so reverse */
    uint8_t key[pubkey_size];
    for ( i = 0; i < pubkey_size; i++ )
        key[i] = *(pubkey + (pubkey_size - i - 1));

    /* create RSA public key struct */
    RSA *rsa_pubkey = RSA_new();
    if ( rsa_pubkey == NULL ) {
        ERROR("Error: failed to allocate key\n");
        return false;
    }
    rsa_pubkey->n = BN_bin2bn(key, pubkey_size, NULL);

    /* uses fixed exponent (LCP_SIG_EXPONENT) */
    char exp[32];
    snprintf(exp, sizeof(exp), "%u", LCP_SIG_EXPONENT);
    rsa_pubkey->e = NULL;
    BN_dec2bn(&rsa_pubkey->e, exp);
    rsa_pubkey->d = rsa_pubkey->p = rsa_pubkey->q = NULL;

    /* first create digest of data */
    tb_hash_t digest;
    if ( !hash_buffer(data, data_size, &digest, TB_HALG_SHA1_LG) ) {
        ERROR("Error: failed to hash list\n");
        RSA_free(rsa_pubkey);
        return false;
    }
    if ( verbose ) {
        LOG("digest: ");
        print_hex("", &digest, get_hash_size(TB_HALG_SHA1_LG));
    }

    /* sigblock is little-endian and openssl wants big-endian, so reverse */
    uint8_t sigblock[pubkey_size];
    if ( is_sig_little_endian ) {
        for ( i = 0; i < pubkey_size; i++ )
            sigblock[i] = *(sig + (pubkey_size - i - 1));
        sig = sigblock;
    }

    if ( verbose ) {
        /* raw decryption of sigblock */
        uint8_t unsig[pubkey_size];
        if ( RSA_public_decrypt(pubkey_size, sig, unsig, rsa_pubkey,
                                RSA_NO_PADDING) == -1 ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to decrypt sig: %s\n", 
                  ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
        }
        else {
            LOG("decrypted sig:\n");
            print_hex("", unsig, pubkey_size);
        }
    }

    /* verify digest */
    if ( !RSA_verify(NID_sha1, (const unsigned char *)&digest,
                     get_hash_size(TB_HALG_SHA1_LG), (uint8_t *)sig, pubkey_size,
                     rsa_pubkey) ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to verify list: %s\n", 
              ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        RSA_free(rsa_pubkey);
        return false;
    }

    RSA_free(rsa_pubkey);
    return true;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
