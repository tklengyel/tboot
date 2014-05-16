/*
 * pollist2.c:
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
#include "pollist2.h"
#include "polelt.h"
#include "lcputils.h"
#include "pollist1.h" 

lcp_list_t *read_policy_list_file(const char *file, bool fail_ok,
        bool *no_sigblock_ok)
{
    LOG("[read_policy_list_file]\n");
    if ( file == NULL || *file == '\0' || no_sigblock_ok == NULL )
        return NULL;

    /* read existing file, if it exists */
    size_t len;
    lcp_list_t *pollist = read_file(file, &len, fail_ok);
    if ( pollist == NULL )
        return NULL;

    uint16_t  version ;
    memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
    if ( version == LCP_TPM12_POLICY_LIST_VERSION ){
        LOG("read_policy_list_file: version=0x0100\n");
        bool no_sigblock;
        if ( !verify_tpm12_policy_list(&(pollist->tpm12_policy_list),
                      len, &no_sigblock, true) ) {
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
        lcp_signature_t *sig = get_tpm12_signature(&(pollist->tpm12_policy_list));
        if ( sig != NULL && no_sigblock ) {
            LOG("input file has no sig_block\n");
            size_t keysize = sig->pubkey_size;
            pollist = realloc(pollist, len + keysize);
            if ( pollist == NULL )
                return NULL;
            memset((void *)pollist + len, 0, keysize);
        }
        *no_sigblock_ok = no_sigblock;
        LOG("read policy list file succeed!\n");
        return pollist;
    }
    else if ( version == LCP_TPM20_POLICY_LIST_VERSION ) {
        LOG("read_policy_list_file: version=0x0200\n");
        bool no_sigblock;
        if ( !verify_tpm20_policy_list(&(pollist->tpm20_policy_list),
                     len, &no_sigblock, true) ) {
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
        lcp_signature_t2 *sig = get_tpm20_signature(&(pollist->tpm20_policy_list));
        if ( sig != NULL && no_sigblock ) {
            LOG("input file has no sig_block\n");
            size_t keysize = 0;
            if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_RSASSA ) {
                LOG("read_policy_list_file: sig_alg == TPM_ALG_RSASSA\n");
                keysize = sig->rsa_signature.pubkey_size;
                pollist = realloc(pollist, len + keysize);
            }
            else if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_ECDSA ) {
                LOG("read_policy_list_file: sig_alg == TPM_ALG_ECDSA\n");
                keysize = sig->ecc_signature.pubkey_size;
                pollist = realloc(pollist, len + keysize);
            }

            if ( pollist == NULL )
                return NULL;
            memset((void *)pollist + len, 0, keysize);
        }
        *no_sigblock_ok = no_sigblock;

        LOG("read policy list file succeed!\n");
        return pollist;
    }

    return NULL;
}

bool verify_tpm20_policy_list(const lcp_policy_list_t2 *pollist, size_t size,
        bool *no_sigblock, bool size_is_exact)
{
    LOG("[verify_tpm20_policy_list]\n");
    if ( pollist == NULL )
        return false;

    if ( size < sizeof(*pollist) ) {
        ERROR("Error: data is too small (%u)\n", size);
        return false;
    }

    if ( pollist->version < LCP_TPM20_POLICY_LIST_VERSION ||
            MAJOR_VER(pollist->version) != MAJOR_VER( LCP_TPM20_POLICY_LIST_VERSION ) ) {
        ERROR("Error: unsupported version 0x%04x\n", pollist->version);
        return false;
    }

    if ( pollist->sig_alg != TPM_ALG_NULL &&
            pollist->sig_alg != TPM_ALG_RSASSA &&
            pollist->sig_alg != TPM_ALG_ECDSA &&
            pollist->sig_alg != TPM_ALG_SM2 ) {
        ERROR("Error: unsupported sig_alg %u\n", pollist->sig_alg);
        return false;
    }

    /* verify policy_elements_size */
    size_t base_size = offsetof(lcp_policy_list_t2, policy_elements);
    /* no sig, so size should be exact */
    if ( pollist->sig_alg == TPM_ALG_NULL ) {
        if ( size_is_exact &&
                base_size + pollist->policy_elements_size != size ) {
            ERROR("Error: size incorrect (no sig): 0x%x != 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
        else if ( !size_is_exact &&
                base_size + pollist->policy_elements_size > size ) {
            ERROR("Error: size incorrect (no sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
    }
    /* verify size exactly later, after check sig field */
    else if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        LOG("verify_tpm20_policy_list: sig_alg == TPM_ALG_RSASSA\n");
        if ( base_size + sizeof(lcp_rsa_signature_t) +
                pollist->policy_elements_size  > size ) {
            ERROR("Error: size incorrect (sig min): 0x%x > 0x%x\n",
                    base_size + sizeof(lcp_rsa_signature_t) +
                    pollist->policy_elements_size, size);
            return false;
        }
    }  
    else if ( pollist->sig_alg == TPM_ALG_ECDSA) {
        LOG("verify_tpm20_policy_list: sig_alg == TPM_ALG_ECDSA\n");
        if ( base_size + sizeof(lcp_ecc_signature_t) +
                pollist->policy_elements_size  > size ) {
            ERROR("Error: size incorrect (sig min): 0x%x > 0x%x\n",
                    base_size + sizeof(lcp_rsa_signature_t) +
                    pollist->policy_elements_size, size);
            return false;
        }
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG ("verify_tpm20_policy_list: sig_alg == TPM_ALG_SM2\n");
        return false;
    }

    /* verify sum of policy elements' sizes */
    uint32_t elts_size = 0;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size < pollist->policy_elements_size ) {
        if ( elts_size + elt->size > pollist->policy_elements_size ) {
            ERROR("Error: size incorrect (elt size): 0x%x > 0x%x\n",
                    elts_size + elt->size, pollist->policy_elements_size);
            return false;
        }
        elts_size += elt->size;
        elt = (void *)elt + elt->size;
    }
    if ( elts_size != pollist->policy_elements_size ) {
        ERROR("Error: size incorrect (elt size): 0x%x != 0x%x\n",
                elts_size, pollist->policy_elements_size);
        return false;
    }

    /* verify sig */
    if ( pollist->sig_alg == TPM_ALG_RSASSA ||
         pollist->sig_alg == TPM_ALG_ECDSA ||
         pollist->sig_alg == TPM_ALG_SM2 ) {
        lcp_signature_t2 *sig = (lcp_signature_t2 *)
            ((void *)&pollist->policy_elements + pollist->policy_elements_size);

        /* check size w/ sig_block */
        if ( !size_is_exact && (base_size + pollist->policy_elements_size +
                                get_tpm20_signature_size(sig, pollist->sig_alg) >
                                size + sig->rsa_signature.pubkey_size) ) {
            ERROR("Error: size incorrect (sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size +
                    get_tpm20_signature_size(sig, pollist->sig_alg),
                    size + sig->rsa_signature.pubkey_size);
            return false;
        }
        else if ( size_is_exact && base_size + pollist->policy_elements_size +
                get_tpm20_signature_size(sig,pollist->sig_alg) != size ) {
            /* check size w/o sig_block */
            if ( base_size + pollist->policy_elements_size +
                    get_tpm20_signature_size(sig, pollist->sig_alg) !=
                    size + sig->rsa_signature.pubkey_size ) {
                ERROR("Error: size incorrect (sig exact): 0x%x != 0x%x\n",
                        base_size + pollist->policy_elements_size +
                        get_tpm20_signature_size(sig, pollist->sig_alg),
                        size + sig->rsa_signature.pubkey_size);
                return false;
            }
            else {
                if ( no_sigblock != NULL )
                    *no_sigblock = true;
            }
        }
        else {
            if ( no_sigblock != NULL )
                *no_sigblock = false;
            if ( !verify_tpm20_pollist_sig(pollist) ) {
                ERROR("Error: signature does not verify\n");
                return false;
            }
        }
    }
    else {
        if ( no_sigblock != NULL )
            *no_sigblock = false;
    }

    LOG("verify tpm20 policy list succeed!\n");
    return true;

}

void display_tpm20_policy_list(const char *prefix,
        const lcp_policy_list_t2 *pollist, bool brief)
{
    if ( pollist == NULL )
        return;

    if ( prefix == NULL )
        prefix = "";

    DISPLAY("%s version: 0x%x\n", prefix, pollist->version);
    DISPLAY("%s sig_alg: %s\n", prefix, sig_alg_to_str(pollist->sig_alg));
    DISPLAY("%s policy_elements_size: 0x%x (%u)\n", prefix,
            pollist->policy_elements_size, pollist->policy_elements_size);

    char new_prefix[strlen(prefix)+8];
    snprintf(new_prefix, sizeof(new_prefix), "%s    ", prefix);
    unsigned int i = 0;
    size_t elts_size = pollist->policy_elements_size;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        DISPLAY("%s policy_element[%u]:\n", prefix, i++);
        display_policy_element(new_prefix, elt, brief);
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig != NULL ) {
        DISPLAY("%s signature:\n", prefix);
        display_tpm20_signature(new_prefix, sig, pollist->sig_alg, brief);
        if ( verify_tpm20_pollist_sig(pollist) )
            DISPLAY("%s signature verifies\n", prefix);
        else
            DISPLAY("%s signature fails to verify\n", prefix);
    }
}

lcp_policy_list_t2 *create_empty_tpm20_policy_list(void)
{ 
    LOG("[create_empty_tpm20_policy_list]\n");
    lcp_policy_list_t2 *pollist = malloc(offsetof(lcp_policy_list_t,
                policy_elements));
    if ( pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    pollist->version = LCP_TPM20_POLICY_LIST_VERSION;
    pollist->sig_alg = TPM_ALG_NULL;
    pollist->policy_elements_size = 0;

    LOG("create policy list succeed!\n");
    return pollist;
}

lcp_policy_list_t2 *add_tpm20_policy_element(lcp_policy_list_t2 *pollist,
        const lcp_policy_element_t *elt)
{
    LOG("[add_tpm20_policy_element]\n");
    if ( pollist == NULL || elt == NULL )
        return NULL;

    /* adding a policy element requires growing the policy list */
    size_t old_size = get_tpm20_policy_list_size(pollist);
    lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + elt->size);
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
            old_size - offsetof(lcp_policy_list_t2, policy_elements));
    memcpy(&new_pollist->policy_elements, elt, elt->size);
    new_pollist->policy_elements_size += elt->size;

    LOG("add tpm20 policy element succeed\n");
    return new_pollist;
}

bool del_tpm20_policy_element(lcp_policy_list_t2 *pollist, uint32_t type)
{
    if ( pollist == NULL )
        return false;

    /* find first element of specified type (there should only be one) */
    size_t elts_size = pollist->policy_elements_size;
    lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        if ( elt->type == type ) {
            /* move everything up */
            size_t tot_size = get_tpm20_policy_list_size(pollist);
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

bool verify_tpm20_pollist_sig(const lcp_policy_list_t2 *pollist)
{
    LOG("[verify_tpm20_pollist_sig]\n");
    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig == NULL )
        return true;

    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        return verify_signature((const unsigned char *)pollist,
                get_tpm20_policy_list_size(pollist) - sig->rsa_signature.pubkey_size,
                sig->rsa_signature.pubkey_value, sig->rsa_signature.pubkey_size,
                get_tpm20_sig_block(pollist), true);
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        LOG("verify_tpm20_pollist_sig: sig_alg == TPM_ALG_ECDSA\n");
        return false;
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG("verify_tpm20_pollist_sig: sig_alg == TPM_ALG_SM2\n");
        return false;
    }

    return false;
}

void display_tpm20_signature(const char *prefix, const lcp_signature_t2 *sig,
        const uint16_t sig_alg, bool brief)
{
    if( sig_alg == TPM_ALG_RSASSA) {
        char new_prefix[strlen(prefix)+8];
        snprintf(new_prefix, sizeof(new_prefix), "%s\t", prefix);

        DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
                sig->rsa_signature.revocation_counter,
                sig->rsa_signature.revocation_counter);
        DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix,
                sig->rsa_signature.pubkey_size,
                sig->rsa_signature.pubkey_size);

        if ( brief )
            return;

        DISPLAY("%s pubkey_value:\n", prefix);
        print_hex(new_prefix, sig->rsa_signature.pubkey_value,
                sig->rsa_signature.pubkey_size);
        DISPLAY("%s sig_block:\n", prefix);
        print_hex(new_prefix, (void *)&sig->rsa_signature.pubkey_value +
                sig->rsa_signature.pubkey_size, sig->rsa_signature.pubkey_size);
    }
    else if ( sig_alg == TPM_ALG_ECDSA ) {
        char new_prefix[strlen(prefix)+8];
        snprintf(new_prefix, sizeof(new_prefix), "%s\t", prefix);

        DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
                sig->ecc_signature.revocation_counter,
                sig->ecc_signature.revocation_counter);
        DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix,
                sig->ecc_signature.pubkey_size,
                sig->ecc_signature.pubkey_size);
        DISPLAY("%s reserved: 0x%x (%u)\n", prefix,
                sig->ecc_signature.reserved, sig->ecc_signature.reserved);

        if ( brief )
            return;

        DISPLAY("%s qx:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx,
                sig->ecc_signature.pubkey_size/2);
        DISPLAY("%s qy:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size/2, sig->ecc_signature.pubkey_size/2);
        DISPLAY("%s r:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size, sig->ecc_signature.pubkey_size/2);
        DISPLAY("%s s:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size + sig->ecc_signature.pubkey_size/2,
                sig->ecc_signature.pubkey_size/2);
    }
    else if ( sig_alg == TPM_ALG_SM2 ) {
        LOG("display_tpm20_signature: sig_alg == TPM_ALG_SM2\n");
    }
}

lcp_policy_list_t2 *add_tpm20_signature(lcp_policy_list_t2 *pollist,
        const lcp_signature_t2 *sig, const uint16_t sig_alg)
{
    LOG("[add_tpm20_signature]\n");
    if ( pollist == NULL || sig == NULL ) {
        LOG("add_tpm20_signature: pollist == NULL || sig == NULL\n");
        return NULL;
    }

    if ( sig_alg == TPM_ALG_RSASSA) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_RSASSA\n");
        /* adding a signature requires growing the policy list */
        size_t old_size = get_tpm20_policy_list_size(pollist);
        size_t sig_size = sizeof(lcp_rsa_signature_t) +
                                 2*sig->rsa_signature.pubkey_size;
        LOG("add_tpm20_signature: sizeof(lcp_rsa_signature_t)=%d\n",
                sizeof(lcp_rsa_signature_t));
        lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + sig_size);
        if ( new_pollist == NULL ) {
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }

        /* realloc() copies over previous contents */

        size_t sig_begin = old_size;
        /* if a signature already exists, replace it */
        lcp_signature_t2 *curr_sig = get_tpm20_signature(new_pollist);
        if ( curr_sig != NULL )
            sig_begin = (void *)curr_sig - (void *)new_pollist;
        memcpy((void *)new_pollist + sig_begin, sig, sig_size);

        return new_pollist;
    }
    else if ( sig_alg == TPM_ALG_ECDSA ) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_ECDSA\n");
        /* adding a signature requires growing the policy list */
        size_t old_size = get_tpm20_policy_list_size(pollist);
        size_t sig_size = sizeof(lcp_ecc_signature_t) +
                2*sig->ecc_signature.pubkey_size;
        lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + sig_size);
        if ( new_pollist == NULL ) {
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }

        /* realloc() copies over previous contents */

        size_t sig_begin = old_size;
        /* if a signature already exists, replace it */
        lcp_signature_t2 *curr_sig = get_tpm20_signature(new_pollist);
        if ( curr_sig != NULL )
            sig_begin = (void *)curr_sig - (void *)new_pollist;

        memcpy((void *)new_pollist + sig_begin, sig, sig_size);

        LOG("add tpm20 signature succeed!\n");
        return new_pollist;
    }
    else if ( sig_alg == TPM_ALG_SM2 ) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_SM2\n");
        return NULL;
    }

    return NULL;
}

unsigned char *get_tpm20_sig_block(const lcp_policy_list_t2 *pollist)
{
    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return NULL;
        return (unsigned char *)&sig->rsa_signature.pubkey_value +
                sig->rsa_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return NULL;
        return (unsigned char *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG("get_tpm_20_sig_block: sig_alg == TPM_ALG_SM2\n");
        return NULL;
    }

    return NULL;
}

void calc_tpm20_policy_list_hash(const lcp_policy_list_t2 *pollist,
        lcp_hash_t2 *hash, uint16_t hash_alg)
{
    LOG("[calc_tpm20_policy_list_hash]\n");
    uint8_t *buf_start = (uint8_t *)pollist;
    size_t len = get_tpm20_policy_list_size(pollist);

    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        LOG("calc_tpm20_policy_list_hash: sig_alg == TPM_ALG_RSASSA\n");
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->rsa_signature.pubkey_value;
        len = sig->rsa_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        LOG("calc_tpm20_policy_list_hash: sig_alg == TPM_ALG_ECDSA\n");
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->ecc_signature.qx + sig->ecc_signature.pubkey_size;
        len = sig->ecc_signature.pubkey_size;
    }

    hash_buffer(buf_start, len, (tb_hash_t *)hash, hash_alg);
}

bool write_tpm20_policy_list_file(const char *file,
                const lcp_policy_list_t2 *pollist)
{
    LOG("[write_tpm20_policy_list_file]\n");
    size_t len = get_tpm20_policy_list_size(pollist);

    /* check if sig_block all 0's--if so then means there was no sig_block
       when file was read but empty one was added, so don't write it */
    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig != NULL ) {
        if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
            LOG("write_tpm20_policy_list_file: sig_alg == TPM_ALG_RSASSA\n");
            uint8_t *sig_block = (uint8_t *)&sig->rsa_signature.pubkey_value +
                                         sig->rsa_signature.pubkey_size;
            while ( sig_block < ((uint8_t *)pollist + len) ) {
                if ( *sig_block++ != 0 )
                    break;
            }
            /* all 0's */
            if ( sig_block == ((uint8_t *)pollist + len) ) {
                LOG("output file has no sig_block\n");
                len -= sig->rsa_signature.pubkey_size;
            }
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
