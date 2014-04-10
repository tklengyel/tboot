/*
 * poldata.c:
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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "poldata.h"
#include "pollist2.h"
#include "lcputils.h"
#include "pollist1.h"

size_t get_policy_data_size(const lcp_policy_data_t2 *poldata)
{
    LOG("[get_policy_data_size]\n");
    size_t size = offsetof(lcp_policy_data_t2, policy_lists);
    const lcp_list_t *pollist = &poldata->policy_lists[0];

    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        uint16_t  version ;
        memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
        if ( version == LCP_TPM12_POLICY_LIST_VERSION ) {
	    LOG("get_policy_data_size: version=0x0100\n");
            size += get_tpm12_policy_list_size(&(pollist->tpm12_policy_list));
            pollist = (void *)pollist +
                    get_tpm12_policy_list_size(&(pollist->tpm12_policy_list));
        }
        else if ( version == LCP_TPM20_POLICY_LIST_VERSION ) {
            LOG("get_policy_data_size: version=0x0200\n");
            size += get_tpm20_policy_list_size(&(pollist->tpm20_policy_list));
            pollist = (void *)pollist +
                    get_tpm20_policy_list_size(&(pollist->tpm20_policy_list));
        }
    }

    LOG("get_policy_data_size succeed! size = %x (%u)\n",
            (unsigned int)size, (unsigned int)size);
    return size;
}

bool verify_policy_data(const lcp_policy_data_t2 *poldata, size_t size)
{
    LOG("[verify_policy_data]\n");
    if ( offsetof(lcp_policy_data_t2, policy_lists) >= size ) {
        ERROR("Error: policy data too small\n");
        return false;
    }

    if ( strcmp(poldata->file_signature, LCP_POLICY_DATA_FILE_SIGNATURE) != 0 ) {
        ERROR("Error: policy data file signature invalid (%s): \n",
              poldata->file_signature);
        return false;
    }

    if ( poldata->reserved[0] != 0 || poldata->reserved[1] != 0 ||
         poldata->reserved[2] != 0 ) {
        ERROR("Error: policy data reserved fields not 0: %u, %u, %u\n",
              poldata->reserved[0], poldata->reserved[1], poldata->reserved[2]);
        return false;
    }

    if ( poldata->num_lists == 0 || poldata->num_lists >= LCP_MAX_LISTS ) {
        ERROR("Error: too many lists: %u\n", poldata->num_lists);
        return false;
    }

    /* try to bound size as closely as possible */
    const lcp_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        LOG("verifying list %u:\n", i);
        uint16_t version ;
        memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
        if ( version == LCP_TPM12_POLICY_LIST_VERSION ) {
             if ( !verify_tpm12_policy_list(&(pollist->tpm12_policy_list),
                           size, NULL, false) )
                 return false;

             pollist = (void *)pollist +
                     get_tpm12_policy_list_size(&(pollist->tpm12_policy_list));
        }
        else if ( version == LCP_TPM20_POLICY_LIST_VERSION ) {
             if ( !verify_tpm20_policy_list(&(pollist->tpm20_policy_list),
                           size, NULL, false) )
                 return false;

             pollist = (void *)pollist +
                     get_tpm20_policy_list_size(&(pollist->tpm20_policy_list));
        }
    }

    LOG("verify policy data succeed!\n");
    return true;
}

void display_policy_data(const char *prefix, const lcp_policy_data_t2 *poldata,
                         bool brief)
{
    if ( poldata == NULL )
        return;

    if ( prefix == NULL )
        prefix = "";

    DISPLAY("%s file_signature: %s\n", prefix, poldata->file_signature);
    DISPLAY("%s num_lists: %u\n", prefix, poldata->num_lists);

    char new_prefix[strlen(prefix)+8];
    sprintf(new_prefix, "%s    ", prefix);
    const lcp_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        DISPLAY("%s list %u:\n", prefix, i);
        uint16_t version ;
        memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
        if ( version == LCP_TPM12_POLICY_LIST_VERSION ) {
            display_tpm12_policy_list(new_prefix,
                    &(pollist->tpm12_policy_list), brief);
            pollist = (void *)pollist +
                    get_tpm12_policy_list_size(&(pollist->tpm12_policy_list));
        }
        if ( version == LCP_TPM20_POLICY_LIST_VERSION ) {
            display_tpm20_policy_list(new_prefix,
                    &(pollist->tpm20_policy_list), brief);
            pollist = (void *)pollist +
                    get_tpm20_policy_list_size(&(pollist->tpm20_policy_list));
        }
    }
}

lcp_policy_data_t2 *add_tpm12_policy_list(lcp_policy_data_t2 *poldata,
                                   const lcp_policy_list_t *pollist)
{
    if ( poldata == NULL || pollist == NULL )
        return NULL;

    LOG("[add_tpm12_policy_list]\n");
    /* adding a policy list requires growing the policy data */
    size_t old_size = get_policy_data_size(poldata);
    size_t list_size = get_tpm12_policy_list_size(pollist);
    lcp_policy_data_t2 *new_poldata = realloc(poldata, old_size + list_size);
    if ( new_poldata == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(poldata);
        return NULL;
    }

    /* realloc() copies over previous contents */
    /* add to end */
    memcpy((void *)new_poldata + old_size, pollist, list_size);
    new_poldata->num_lists++;

    LOG("add tpm12 policy list succeed!\n");
    return new_poldata;
}

lcp_policy_data_t2 *add_tpm20_policy_list(lcp_policy_data_t2 *poldata,
                                   const lcp_policy_list_t2 *pollist)
{
    LOG("[add_tpm20_policy_list]\n");
    if ( poldata == NULL || pollist == NULL )
        return NULL;

    /* adding a policy list requires growing the policy data */
    size_t old_size = get_policy_data_size(poldata);
    size_t list_size = get_tpm20_policy_list_size(pollist);
    lcp_policy_data_t2 *new_poldata = realloc(poldata, old_size + list_size);
    if ( new_poldata == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(poldata);
        return NULL;
    }

    /* realloc() copies over previous contents */
    /* add to end */
    memcpy((void *)new_poldata + old_size, pollist, list_size);
    new_poldata->num_lists++;

    LOG("add tpm20 policy list succeed!\n");
    return new_poldata;
}

void calc_policy_data_hash(const lcp_policy_data_t2 *poldata, lcp_hash_t2 *hash,
                           uint16_t hash_alg)
{
    LOG("[calc_policy_data_hash]\n");
    size_t hash_size = get_lcp_hash_size(hash_alg);
    uint8_t hash_list[hash_size * LCP_MAX_LISTS];

    memset(hash_list, 0, sizeof(hash_list));

    /* accumulate each list's msmt to list */
    lcp_hash_t2 *curr_hash = (lcp_hash_t2 *)hash_list;
    const lcp_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        uint16_t  version ;
        memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
        if ( version == LCP_TPM12_POLICY_LIST_VERSION ) {
            LOG("calc_policy_data_hash:version=0x0100\n" );
            calc_tpm12_policy_list_hash(&(pollist->tpm12_policy_list),
                    curr_hash, hash_alg);
            pollist = (void *)pollist +
                    get_tpm12_policy_list_size(&(pollist->tpm12_policy_list));
            curr_hash = (void *)curr_hash + hash_size;
        }
	if ( version == LCP_TPM20_POLICY_LIST_VERSION ) {
            LOG("calc_policy_data_hash:version=0x0200\n" );
            calc_tpm20_policy_list_hash(&(pollist->tpm20_policy_list),
                    curr_hash, hash_alg);
            pollist = (void *)pollist +
                    get_tpm20_policy_list_size(&(pollist->tpm20_policy_list));
            curr_hash = (void *)curr_hash + hash_size;
        }
    }

    /* hash list */
    hash_buffer(hash_list, hash_size * poldata->num_lists, (tb_hash_t *)hash,
                hash_alg);

    LOG("policy_data_hash:");
    print_hex("", hash, get_lcp_hash_size(hash_alg));

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
