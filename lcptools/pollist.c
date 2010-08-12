/*
 * pollist.c:
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
#include <string.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "polelt_plugin.h"
#include "pollist.h"
#include "polelt.h"
#include "lcputils2.h"
#include "../include/lcp2_fns.h"

lcp_policy_list_t *create_empty_policy_list(void)
{ 
    lcp_policy_list_t *pollist = malloc(offsetof(lcp_policy_list_t,
                                                 policy_elements));
    if ( pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    pollist->version = LCP_DEFAULT_POLICY_LIST_VERSION;
    pollist->reserved = 0;
    pollist->sig_alg = LCP_POLSALG_NONE;
    pollist->policy_elements_size = 0;

    return pollist;
}

lcp_policy_list_t *add_policy_element(lcp_policy_list_t *pollist,
                                      const lcp_policy_element_t *elt)
{
    if ( pollist == NULL || elt == NULL )
        return NULL;

    /* adding a policy element requires growing the policy list */
    size_t old_size = get_policy_list_size(pollist);
    lcp_policy_list_t *new_pollist = realloc(pollist, old_size + elt->size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    /* realloc() copies over previous contents */
    /* we add at the beginning of the elements list (don't want to overwrite
       a signature) */
    memmove((void *)&new_pollist->policy_elements + elt->size,
            &new_pollist->policy_elements,
            old_size - offsetof(lcp_policy_list_t, policy_elements));
    memcpy(&new_pollist->policy_elements, elt, elt->size);
    new_pollist->policy_elements_size += elt->size;

    return new_pollist;
}

bool del_policy_element(lcp_policy_list_t *pollist, uint32_t type)
{
    if ( pollist == NULL )
        return false;

    /* find first element of specified type (there should only be one) */
    size_t elts_size = pollist->policy_elements_size;
    lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        if ( elt->type == type ) {
            /* move everything up */
            size_t tot_size = get_policy_list_size(pollist);
            size_t elt_size = elt->size;
            memmove(elt, (void *)elt + elt_size,
                    tot_size - ((void *)elt + elt_size - (void *)pollist));
            pollist->policy_elements_size -= elt_size;

            return true;
        }
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }
    return false;
}

bool verify_pollist_sig(const lcp_policy_list_t *pollist)
{
    lcp_signature_t *sig = get_signature(pollist);
    if ( sig == NULL )
        return true;

    return verify_signature((const unsigned char *)pollist,
                            get_policy_list_size(pollist) - sig->pubkey_size,
                            sig->pubkey_value, sig->pubkey_size,
                            get_sig_block(pollist), true);
}

#if 0


    unsigned int i;

    /* policy key is little-endian and openssl wants big-endian, so reverse */
    uint8_t key[sig->pubkey_size];
    for ( i = 0; i < sig->pubkey_size; i++ )
        key[i] = *( + (sig->pubkey_size - i - 1));

    /* create RSA public key struct */
    RSA *pubkey = RSA_new();
    if ( pubkey == NULL ) {
        ERROR("Error: failed to allocate key\n");
        return false;
    }
    pubkey->n = BN_bin2bn(key, sig->pubkey_size, NULL);

    /* uses fixed exponent (LCP_SIG_EXPONENT) */
    char exp[32];
    snprintf(exp, sizeof(exp), "%u", LCP_SIG_EXPONENT);
    pubkey->e = NULL;
    BN_dec2bn(&pubkey->e, exp);
    pubkey->d = pubkey->p = pubkey->q = NULL;

    /* first create digest of list (all except sig_block) */
    tb_hash_t digest;
    if ( !hash_buffer(
                      
                      &digest, TB_HALG_SHA1) ) {
        ERROR("Error: failed to hash list\n");
        RSA_free(pubkey);
        return false;
    }
    if ( verbose ) {
        LOG("digest: ");
        print_hex("", &digest, get_hash_size(TB_HALG_SHA1));
    }

    /* sigblock is little-endian and openssl wants big-endian, so reverse */
    uint8_t sigblock[sig->pubkey_size];
    for ( i = 0; i < sig->pubkey_size; i++ )
        sigblock[i] = *( + (sig->pubkey_size - i - 1));

    if ( verbose ) {
        /* raw decryption of sigblock */
        uint8_t unsig[sig->pubkey_size];
        if ( RSA_public_decrypt(sig->pubkey_size, sigblock, unsig, pubkey,
                                RSA_NO_PADDING) == -1 ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to decrypt sig: %s\n", 
                  ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
        }
        else {
            LOG("decrypted sig:\n");
            print_hex("", unsig, sig->pubkey_size);
        }
    }

    /* verify digest */
    if ( !RSA_verify(NID_sha1, (const unsigned char *)&digest,
                     get_hash_size(TB_HALG_SHA1), sigblock, sig->pubkey_size,
                     pubkey) ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to verify list: %s\n", 
              ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        RSA_free(pubkey);
        return false;
    }

    RSA_free(pubkey);
    return true;
}
#endif

lcp_policy_list_t *add_signature(lcp_policy_list_t *pollist,
                                 const lcp_signature_t *sig)
{
    if ( pollist == NULL || sig == NULL )
        return NULL;

    /* adding a signature requires growing the policy list */
    size_t old_size = get_policy_list_size(pollist);
    size_t sig_size = sizeof(*sig) + 2*sig->pubkey_size;
    lcp_policy_list_t *new_pollist = realloc(pollist, old_size + sig_size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    /* realloc() copies over previous contents */

    size_t sig_begin = old_size;
    /* if a signature already exists, replace it */
    lcp_signature_t *curr_sig = get_signature(new_pollist);
    if ( curr_sig != NULL )
        sig_begin = (void *)curr_sig - (void *)new_pollist;
    memcpy((void *)new_pollist + sig_begin, sig, sig_size);

    return new_pollist;
}

unsigned char *get_sig_block(const lcp_policy_list_t *pollist)
{
    lcp_signature_t *sig = get_signature(pollist);
    if ( sig == NULL )
        return NULL;
    return (unsigned char *)&sig->pubkey_value + sig->pubkey_size;
}

lcp_policy_list_t *read_policy_list_file(const char *file, bool fail_ok,
                                         bool *no_sigblock_ok)
{
    if ( file == NULL || *file == '\0' || no_sigblock_ok == NULL )
        return NULL;

    /* read existing file, if it exists */
    size_t len;
    lcp_policy_list_t *pollist = read_file(file, &len, fail_ok);
    if ( pollist == NULL )
        return NULL;

    bool no_sigblock = false;
    if ( !verify_policy_list(pollist, len, &no_sigblock, true,
                             true, true) ) {
        free(pollist);
        return NULL;
    }

    if ( !*no_sigblock_ok && no_sigblock ) {
        ERROR("Error: policy list does not have sig_block\n");
        free(pollist);
        return NULL;
    }

    /* if there is no sig_block then create one w/ all 0s so that
       get_policy_list_size() will work correctly; it will be stripped
       when writing it back */
    lcp_signature_t *sig = get_signature(pollist);
    if ( sig != NULL && no_sigblock ) {
        LOG("input file has no sig_block\n");
        size_t keysize = sig->pubkey_size;
        pollist = realloc(pollist, len + keysize);
        if ( pollist == NULL )
            return NULL;
        memset((void *)pollist + len, 0, keysize);
    }
    *no_sigblock_ok = no_sigblock;

    return pollist;
}

bool write_policy_list_file(const char *file, const lcp_policy_list_t *pollist)
{
    size_t len = get_policy_list_size(pollist);

    /* check if sig_block all 0's--if so then means there was no sig_block
       when file was read but empty one was added, so don't write it */
    lcp_signature_t *sig = get_signature(pollist);
    if ( sig != NULL ) {
        uint8_t *sig_block = (uint8_t *)&sig->pubkey_value + sig->pubkey_size;
        while ( sig_block < ((uint8_t *)pollist + len) ) {
            if ( *sig_block++ != 0 )
                break;
        }
        /* all 0's */
        if ( sig_block == ((uint8_t *)pollist + len) ) {
            LOG("output file has no sig_block\n");
            len -= sig->pubkey_size;
        }
    }

    return write_file(file, pollist, len);
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
