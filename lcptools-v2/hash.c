/*
 * hash.c: support functions for tb_hash_t type
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/evp.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"

/*
 * are_hashes_equal
 *
 * compare whether two hash values are equal.
 *
 */
bool are_hashes_equal(const tb_hash_t *hash1, const tb_hash_t *hash2,
		      uint16_t hash_alg)
{
    if ( ( hash1 == NULL ) || ( hash2 == NULL ) )
        return false;

    if ( hash_alg == TB_HALG_SHA1 )
        return (memcmp(hash1, hash2, SHA1_LENGTH) == 0);
    else if ( hash_alg == TB_HALG_SHA256 )
        return (memcmp(hash1, hash2, SHA256_LENGTH) == 0);
    else if ( hash_alg == TB_HALG_SM3 )
        return (memcmp(hash1, hash2, SM3_LENGTH) == 0);
    else if ( hash_alg == TB_HALG_SHA384 )
        return (memcmp(hash1, hash2, SHA384_LENGTH) == 0);
    else if ( hash_alg == TB_HALG_SHA512 )
        return (memcmp(hash1, hash2, SHA512_LENGTH) == 0);
    else
        return false;
}

/*
 * hash_buffer
 *
 * hash the buffer according to the algorithm
 *
 */
bool hash_buffer(const unsigned char* buf, size_t size, tb_hash_t *hash,
		 uint16_t hash_alg)
{
    if ( hash == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 ) {
        EVP_MD_CTX ctx;
        const EVP_MD *md;

        md = EVP_sha1();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buf, size);
        EVP_DigestFinal(&ctx, hash->sha1, NULL);
        return true;
    }
    else if (hash_alg == TB_HALG_SHA256) {
        EVP_MD_CTX ctx;
        const EVP_MD *md;

        md = EVP_sha256();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buf, size);
        EVP_DigestFinal(&ctx, hash->sha256, NULL);
        return true;
    }
    else if (hash_alg == TB_HALG_SHA384) {
        EVP_MD_CTX ctx;
        const EVP_MD *md;

        md = EVP_sha384();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buf, size);
        EVP_DigestFinal(&ctx, hash->sha384, NULL);
        return true;
    }
    else
        return false;
}

/*
 * extend_hash
 *
 * perform "extend" of two hashes (i.e. hash1 = SHA(hash1 || hash2)
 *
 */
bool extend_hash(tb_hash_t *hash1, const tb_hash_t *hash2, uint16_t hash_alg)
{
    uint8_t buf[2*sizeof(tb_hash_t)];

    if ( hash1 == NULL || hash2 == NULL )
        return false;

    if ( hash_alg == TB_HALG_SHA1 ) {
        EVP_MD_CTX ctx;
        const EVP_MD *md;

        memcpy(buf, &(hash1->sha1), sizeof(hash1->sha1));
        memcpy(buf + sizeof(hash1->sha1), &(hash2->sha1), sizeof(hash1->sha1));
        md = EVP_sha1();
        EVP_DigestInit(&ctx, md);
        EVP_DigestUpdate(&ctx, buf, 2*sizeof(hash1->sha1));
        EVP_DigestFinal(&ctx, hash1->sha1, NULL);
        return true;
    }
    else
        return false;
}

void print_hash(const tb_hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL )
        return;

    if ( hash_alg == TB_HALG_SHA1 ) {
        for ( unsigned int i = 0; i < SHA1_LENGTH; i++ ) {
            printf("%02x", hash->sha1[i]);
            if ( i < SHA1_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else if ( hash_alg == TB_HALG_SHA256 ) {
        for ( unsigned int i = 0; i < SHA256_LENGTH; i++ ) {
            printf("%02x", hash->sha256[i]);
            if ( i < SHA256_LENGTH-1 )
                printf(" ");
        }
        printf("\n");
    }
    else
        return;
}

void copy_hash(tb_hash_t *dest_hash, const tb_hash_t *src_hash,
               uint16_t hash_alg)
{
    if ( dest_hash == NULL || dest_hash == NULL )
        return;

    if ( hash_alg == TB_HALG_SHA1 )
        memcpy(dest_hash, src_hash, SHA1_LENGTH);
    else
        return;
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
