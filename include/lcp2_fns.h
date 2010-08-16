/*
 * Copyright 2001 - 2010 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TXT_LCP2_FNS_H__
#define __TXT_LCP2_FNS_H__

/*
 * helper fns
 */

#ifndef PRINT
#define PRINT(...) {}
#endif

#ifndef ERROR
#define ERROR   PRINT
#endif

#ifndef LOG
#define LOG     PRINT
#endif

#ifndef DISPLAY
#define DISPLAY PRINT
#endif


#define MAJOR_VER(v)      ((v) >> 8)
#define MINOR_VER(v)      ((v) & 0xff)

static inline const char *policy_type_to_str(uint8_t type)
{
    static char buf[32] = "";

    if ( type == LCP_POLTYPE_LIST )
        return "list";
    else if ( type == LCP_POLTYPE_ANY )
        return "any";
    else {
        snprintf(buf, sizeof(buf), "unknown (%u)", type);
        return buf;
    }
}

static inline size_t get_policy_size(const lcp_policy_t *pol)
{
    if ( pol == NULL )
        return 0;
    return offsetof(lcp_policy_t, policy_hash) +
           get_hash_size(pol->hash_alg);
}

static inline bool verify_lcp_policy(const lcp_policy_t *pol, size_t size,
                                     bool silent, bool brief)
{
    const char *prefix = "  ";

    (void)brief;        /* quiet compiler warning portbly */

    if ( get_policy_size(pol) > size ) {
        ERROR("Error: policy too big\n");
        return false;
    }

    if ( pol->version < LCP_DEFAULT_POLICY_VERSION ||
         MAJOR_VER(pol->version) != MAJOR_VER(LCP_DEFAULT_POLICY_VERSION) ) {
        ERROR("Error: invalid policy version: 0x%x\n", pol->version);
        return false;
    }

    if ( !silent ) DISPLAY("%s version: 0x%x\n", prefix, pol->version);

    if ( pol->hash_alg != LCP_POLHALG_SHA1 ) {
        ERROR("Error: invalid policy hash alg: %u\n", pol->hash_alg);
        return false;
    }

    if ( !silent )
        DISPLAY("%s hash_alg: %s\n", prefix, hash_alg_to_string(pol->hash_alg));

    if ( pol->policy_type != LCP_POLTYPE_ANY &&
         pol->policy_type != LCP_POLTYPE_LIST ) {
        ERROR("Error: invlaid policy type: %u\n", pol->policy_type);
        return false;
    }

    if ( !silent )
        DISPLAY("%s policy_type: %s\n", prefix,
                policy_type_to_str(pol->policy_type));
    if ( !silent )
        DISPLAY("%s sinit_min_version: 0x%x\n", prefix, pol->sinit_min_version);
    if ( !silent )
        DISPLAY("%s data_revocation_counters: ", prefix);

    for ( unsigned int i = 0; i <  ARRAY_SIZE(pol->data_revocation_counters); i++ )
        if ( !silent ) DISPLAY("%u, ", pol->data_revocation_counters[i]);
    if ( !silent ) DISPLAY("\n");
    if ( !silent )
        DISPLAY("%s policy_control: 0x%x\n", prefix, pol->policy_control);

    if ( pol->reserved1 != 0 || pol->reserved2[0] != 0 ||
         pol->reserved2[1] != 0 ) {
        ERROR("Error: reserved fields not 0: %u, %u, %u\n", pol->reserved1,
              pol->reserved2[0], pol->reserved2[1]);
        return false;
    }

    if ( !silent ) DISPLAY("%s policy_hash: ", prefix);
    if ( !silent )
        print_hex("", &pol->policy_hash, get_hash_size(pol->hash_alg));

    return true;
}

static inline size_t get_signature_size(const lcp_signature_t *sig)
{
    if ( sig == NULL )
        return 0;
    return offsetof(lcp_signature_t, pubkey_value) + 2*sig->pubkey_size;
}

static inline lcp_signature_t *get_signature(const lcp_policy_list_t *pollist)
{
    if ( pollist == NULL )
        return NULL;

    if ( pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15 )
        return NULL;

    return (lcp_signature_t *)((const void *)&pollist->policy_elements +
                               pollist->policy_elements_size);
}

static inline size_t get_policy_list_size(const lcp_policy_list_t *pollist)
{
    size_t size = 0;

    if ( pollist == NULL )
        return 0;

    size = offsetof(lcp_policy_list_t, policy_elements) +
           pollist->policy_elements_size;
    /* add sig size */
    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 )
        size += get_signature_size(get_signature(pollist));
    return size;
}

static void display_signature(const char *prefix, const lcp_signature_t *sig,
                              bool brief)
{
    char new_prefix[strlen(prefix)+8];
    snprintf(new_prefix, sizeof(new_prefix), "%s\t", prefix);

    DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
            sig->revocation_counter, sig->revocation_counter);
    DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix, sig->pubkey_size,
            sig->pubkey_size);

    /* don't display element data for brief output */
    if ( brief )
        return;

    DISPLAY("%s pubkey_value:\n", prefix);
    print_hex(new_prefix, sig->pubkey_value, sig->pubkey_size);
    DISPLAY("%s sig_block:\n", prefix);
    print_hex(new_prefix, (void *)&sig->pubkey_value + sig->pubkey_size,
              sig->pubkey_size);
}

static bool verify_policy_element(const lcp_policy_element_t *elt, size_t size,
                                  bool silent, bool brief)
{
    static const char *elt_type_str[] =
        { "LCP_POLELT_TYPE_MLE", "LCP_POLELT_TYPE_PCONF",
          "LCP_POLELT_TYPE_SBIOS", "LCP_POLELT_TYPE_CUSTOM" };
    const char *prefix = "      ";

    if ( elt == NULL )
        return false;

    if ( size < sizeof(*elt) ) {
        ERROR("Error: data is too small\n");
        return false;
    }

    if ( size != elt->size ) {
        ERROR("Error: data is too small\n");
        return false;
    }

    if ( !silent )
        DISPLAY("%s size: 0x%x (%u)\n", prefix, elt->size, elt->size);

    if ( elt->type < ARRAY_SIZE(elt_type_str) ) {
        if ( !silent )
            DISPLAY("%s type: %s\n", prefix, elt_type_str[elt->type]);
    }
    else {
        ERROR("Error: type is not correct\n");
        return false;
    }

    if ( !silent )
        DISPLAY("%s policy_elt_control: 0x%08x\n", prefix,
                elt->policy_elt_control);

    /* don't display element data for brief output */
    if ( brief )
        return true;

    if ( !silent )
        display_policy_element(prefix, elt);

    return true;
}

static inline bool verify_policy_list(const lcp_policy_list_t *pollist,
              size_t size, bool *no_sigblock, bool size_is_exact,
              bool silent, bool brief)
{
    static const char *sig_alg_str[] =
        { "LCP_POLSALG_NONE", "LCP_POLSALG_RSA_PKCS_15" };
    const char *prefix = "    ";

    if ( pollist == NULL )
        return false;

    if ( size < sizeof(*pollist) ) {
        ERROR("Error: data is too small (%lu)\n", (unsigned long)size);
        return false;
    }

    if ( pollist->version < LCP_DEFAULT_POLICY_LIST_VERSION ||
         MAJOR_VER(pollist->version)
             != MAJOR_VER(LCP_DEFAULT_POLICY_LIST_VERSION) ) {
        ERROR("Error: unsupported version 0x%04x\n", pollist->version);
        return false;
    }

    if ( !silent ) DISPLAY("%s version: 0x%x\n", prefix, pollist->version);

    if ( pollist->reserved != 0 ) {
        ERROR("Error: reserved field must be 0: %u\n", pollist->reserved);
        return false;
    }

    if ( pollist->sig_alg != LCP_POLSALG_NONE &&
         pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15 ) {
        ERROR("Error: unsupported sig_alg %u\n", pollist->sig_alg);
        return false;
    }

    if ( !silent )
        DISPLAY("%s sig_alg: %s\n", prefix, sig_alg_str[pollist->sig_alg]);

    /* verify policy_elements_size */
    size_t base_size = offsetof(lcp_policy_list_t, policy_elements);
    /* no sig, so size should be exact */
    if ( pollist->sig_alg == LCP_POLSALG_NONE ) {
        if ( size_is_exact &&
             base_size + pollist->policy_elements_size != size ) {
            ERROR("Error: size incorrect (no sig): 0x%lx != 0x%lx\n",
                  (unsigned long)(base_size + pollist->policy_elements_size),
                  (unsigned long)size);
            return false;
        }
        else if ( !size_is_exact &&
                  base_size + pollist->policy_elements_size > size ) {
            ERROR("Error: size incorrect (no sig): 0x%lx > 0x%lx\n",
                  (unsigned long)(base_size + pollist->policy_elements_size),
                  (unsigned long)size);
            return false;
        }
    }
    /* verify size exactly later, after check sig field */
    else if ( base_size + sizeof(lcp_signature_t) +
              pollist->policy_elements_size  > size ) {
        ERROR("Error: size incorrect (sig min): 0x%lx > 0x%lx\n",
              (unsigned long)(base_size + sizeof(lcp_signature_t)
                              + pollist->policy_elements_size),
              (unsigned long)size);
        return false;
    }

    if ( !silent )
        DISPLAY("%s policy_elements_size: 0x%x (%u)\n", prefix,
                pollist->policy_elements_size, pollist->policy_elements_size);

    /* verify sum of policy elements' sizes */
    unsigned int i = 0;
    uint32_t elts_size = 0;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size < pollist->policy_elements_size ) {
        if ( !silent ) DISPLAY("%s policy_element[%u]:\n", prefix, i++);

        if ( elts_size + elt->size > pollist->policy_elements_size ) {
            ERROR("Error: size incorrect (elt size): 0x%x > 0x%x\n",
                  elts_size + elt->size, pollist->policy_elements_size);
            return false;
        }

        /* this also displays it */
        if ( !verify_policy_element(elt, elt->size, silent, brief) )
            return false;

        elts_size += elt->size;
        elt = (void *)elt + elt->size;
    }
    if ( elts_size != pollist->policy_elements_size ) {
        ERROR("Error: size incorrect (elt size): 0x%x != 0x%x\n",
              elts_size, pollist->policy_elements_size);
        return false;
    }

    /* verify sig */
    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 ) {
        lcp_signature_t *sig = get_signature(pollist);
        if ( sig == NULL )
            return false;

        if ( !silent ) DISPLAY("%s signature:\n", prefix);
        if ( !silent ) display_signature(prefix, sig, brief);

        /* check size w/ sig_block */
        if ( !size_is_exact && base_size + pollist->policy_elements_size +
             get_signature_size(sig) > size + sig->pubkey_size ) {
            ERROR("Error: size incorrect (sig): 0x%lx > 0x%lx\n",
                  (unsigned long)(base_size + pollist->policy_elements_size
                                  + get_signature_size(sig)),
                  (unsigned long)(size + sig->pubkey_size));
            return false;
        }
        else if ( size_is_exact && base_size + pollist->policy_elements_size +
             get_signature_size(sig) != size ) {
            /* check size w/o sig_block */
            if ( base_size + pollist->policy_elements_size +
                 get_signature_size(sig) != size + sig->pubkey_size ) {
                ERROR("Error: size incorrect (sig exact): 0x%lx != 0x%lx\n",
                      (unsigned long)(base_size + pollist->policy_elements_size
                                      + get_signature_size(sig)),
                      (unsigned long)(size + sig->pubkey_size));
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
            if ( !verify_pollist_sig(pollist) ) {
                ERROR("Error: signature does not verify\n");
                if ( !silent )
                    DISPLAY("%s signature fails to verify\n", prefix);
                return false;
            }
            else {
                if ( !silent )
                    DISPLAY("%s signature verifies\n", prefix);
            }
        }
    }

    return true;
}

static inline void calc_policy_list_hash(const lcp_policy_list_t *pollist,
                                         lcp_hash_t *hash, uint8_t hash_alg)
{
    uint8_t *buf_start = (uint8_t *)pollist;
    size_t len = get_policy_list_size(pollist);

    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 ) {
        lcp_signature_t *sig = get_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->pubkey_value;
        len = sig->pubkey_size;
    }

    hash_buffer(buf_start, len, (tb_hash_t *)hash, hash_alg);
}

static inline size_t get_policy_data_size(const lcp_policy_data_t *poldata)
{
    size_t size = offsetof(lcp_policy_data_t, policy_lists);
    const lcp_policy_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        size += get_policy_list_size(pollist);
        pollist = (void *)pollist + get_policy_list_size(pollist);
    }

    return size;
}

static inline bool verify_policy_data(const lcp_policy_data_t *poldata,
                                      size_t size, bool silent, bool brief)
{
    const char *prefix = "  ";

    if ( poldata == NULL )
        return false;

    if ( offsetof(lcp_policy_data_t, policy_lists) >= size ) {
        ERROR("Error: policy data too small\n");
        return false;
    }

    if ( strcmp(poldata->file_signature, LCP_POLICY_DATA_FILE_SIGNATURE) != 0 ) {
        ERROR("Error: policy data file signature invalid (%s): \n",
              poldata->file_signature);
        return false;
    }

    if ( !silent )
        DISPLAY("%s file_signature: %s\n", prefix, poldata->file_signature);

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

    if ( !silent )
        DISPLAY("%s num_lists: %u\n", prefix, poldata->num_lists);

    /* try to bound size as closely as possible */
    size -= offsetof(lcp_policy_data_t, policy_lists);
    const lcp_policy_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        if ( !silent ) LOG("verifying list %u:\n", i);
        if ( !silent ) DISPLAY("%s list %u:\n", prefix, i);

        /* this also displays it */
        if ( !verify_policy_list(pollist, size, NULL, false, silent, brief) )
            return false;

        size -= get_policy_list_size(pollist);
        pollist = (void *)pollist + get_policy_list_size(pollist);
    }

    return true;
}

static inline void calc_policy_data_hash(const lcp_policy_data_t *poldata,
                                         lcp_hash_t *hash, uint8_t hash_alg)
{
    size_t hash_size = get_hash_size(hash_alg);

    if ( hash_size == 0 )
        return;

    uint8_t hash_list[hash_size * LCP_MAX_LISTS];

    memset(hash_list, 0, sizeof(hash_list));

    /* accumulate each list's msmt to list */
    lcp_hash_t *curr_hash = (lcp_hash_t *)hash_list;
    const lcp_policy_list_t *pollist = &poldata->policy_lists[0];
    for ( unsigned int i = 0; i < poldata->num_lists; i++ ) {
        calc_policy_list_hash(pollist, curr_hash, hash_alg);
        pollist = (void *)pollist + get_policy_list_size(pollist);
        curr_hash = (void *)curr_hash + hash_size;
    }

    /* hash list */
    hash_buffer(hash_list, hash_size * poldata->num_lists, (tb_hash_t *)hash,
                hash_alg);

    return;
}

#endif    /*  __TXT_LCP2_FNS_H__ */
