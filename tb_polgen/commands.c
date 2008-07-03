/*
 * commands.c: handlers for commands
 *
 * Copyright (c) 2006-2007, Intel Corporation
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
#include <zlib.h>
#include <openssl/evp.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/uuid.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

static bool hash_file(const char *filename, bool unzip, tb_hash_t *hash)
{
    FILE *f;
    static char buf[1024];
    EVP_MD_CTX ctx;
    const EVP_MD *md;
    int read_cnt;

    if ( unzip )
        f = gzopen(filename, "rb");
    else
        f = fopen(filename, "rb");

    if ( f == NULL ) {
        error_msg("File %s does not exist\n", filename);
        return false;
    }

    md = EVP_sha1();
    EVP_DigestInit(&ctx, md);
    do {
        if ( unzip )
            read_cnt = gzread(f, buf, sizeof(buf));
        else
            read_cnt = fread(buf, 1, sizeof(buf), f);
        if ( read_cnt == 0 )
            break;

        EVP_DigestUpdate(&ctx, buf, read_cnt);
    } while ( true );
    EVP_DigestFinal(&ctx, hash->sha1, NULL);

    if ( unzip )
        gzclose(f);
    else
        fclose(f);

    return true;
}

bool do_show(const param_data_t *params)
{
    /* read the policy file */
    if ( !read_policy_file(params->policy_file) ) {
        error_msg("Error reading policy file %s\n", params->policy_file);
        return false;
    }

    display_policy();

    return true;
}

bool do_create(const param_data_t *params)
{
    bool existing_policy = false;
    tb_hash_t final_hash, hash;
    bool unzip = true;
    bool is_cmdline = true;
    int i;

    /* read the policy file */
    info_msg("reading existing policy file %s...\n", params->policy_file);
    if ( read_policy_file(params->policy_file) )
        existing_policy = true;

    /* policy_type must be specified for new policy */
    if ( !existing_policy && params->policy_type == -1 ) {
        error_msg("Must specify --policy_type for new policy\n");
        return false;
    }

    modify_policy_index(params->policy_type);

    /*
     * add/replace policies
     */
    /* hash command line and files */
    if ( params->hash_type != TB_HTYPE_ANY ) {
        if ( strlen(params->cmdline) > 0 ) {
            EVP_MD_CTX ctx;
            const EVP_MD *md;
            /* hash command line */
            info_msg("hashing command line \"%s\"...", params->cmdline);
            md = EVP_sha1();
            EVP_DigestInit(&ctx, md);
            EVP_DigestUpdate(&ctx, (unsigned char *)params->cmdline,
                             strlen(params->cmdline));
            EVP_DigestFinal(&ctx, (unsigned char *)&final_hash, NULL);
            if ( verbose ) print_hash(&final_hash, TB_HALG_SHA1);
            is_cmdline = true;
        }
        else
            is_cmdline = false;

        /* hash files */
        info_msg("hashing command input files...\n");
        for ( i = 0; i < params->num_infiles; i++ ) {
            if ( !hash_file(params->infiles[i], unzip, &hash) )
                return false;
            info_msg("file %s hash is...", params->infiles[i]);
            if ( verbose ) print_hash(&hash, TB_HALG_SHA1);

            if ( !is_cmdline && i == 0 )
                memcpy(&final_hash, &hash, sizeof(hash));
            else {
                if ( !extend_hash(&final_hash, &hash, TB_HALG_SHA1) )
                    return false;
            }
            info_msg("cummulative hash is ");
            if ( verbose ) print_hash(&final_hash, TB_HALG_SHA1);
        }
    }
    /* add/replace the policy */
    info_msg("updating policy...\n");
    if ( !replace_policy(&params->uuid, params->hash_type, &final_hash) )
        return false;

    info_msg("writing new policy file...\n");
    if ( !write_policy_file(params->policy_file) )
        return false;

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
