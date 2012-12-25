/*
 * policy.c: support functions for tboot verification launch
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <config.h>
#include <stdarg.h>
#include <types.h>
#include <ctype.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <multiboot.h>
#include <hash.h>
#include <tb_error.h>
#define PRINT printk
#include <tb_policy.h>
#include <mle.h>
#include <tpm.h>
#include <loader.h>
#include <tboot.h>
#include <integrity.h>
#include <lcp2.h>
#include <lcp_hlp.h>
#include <cmdline.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/txt.h>
#include <txt/heap.h>

extern void shutdown(void);
extern void s3_launch(void);

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

extern long s3_flag;

/*
 * policy actions
 */
typedef enum {
    TB_POLACT_CONTINUE,
    TB_POLACT_UNMEASURED_LAUNCH,
    TB_POLACT_HALT,
} tb_policy_action_t;

/* policy map types */
typedef struct {
    tb_error_t         error;
    tb_policy_action_t action;
} tb_policy_map_entry_t;

typedef struct {
    uint8_t                policy_type;
    tb_policy_action_t     default_action;
    tb_policy_map_entry_t  exception_action_table[TB_ERR_MAX];
                           /* have TB_ERR_NONE as last entry */
} tb_policy_map_t;

/* map */
static const tb_policy_map_t g_policy_map[] = {
    { TB_POLTYPE_CONT_NON_FATAL,               TB_POLACT_CONTINUE,
      {
          {TB_ERR_FATAL,                       TB_POLACT_HALT},
          {TB_ERR_TPM_NOT_READY,               TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_TXT_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SINIT_NOT_PRESENT,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_ACMOD_VERIFY_FAILED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_CONT_VERIFY_FAIL,             TB_POLACT_HALT,
      {
          {TB_ERR_MODULE_VERIFICATION_FAILED,  TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_NOT_PRESENT,          TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_INVALID,              TB_POLACT_CONTINUE},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_HALT,                         TB_POLACT_HALT,
      {
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },
};

/* buffer for policy as read from TPM NV */
#define MAX_POLICY_SIZE                             \
    (( MAX_TB_POLICY_SIZE > sizeof(lcp_policy_t) )  \
        ? MAX_TB_POLICY_SIZE                        \
        : sizeof(lcp_policy_t) )
static uint8_t _policy_index_buf[MAX_POLICY_SIZE];

/* default policy */
static const tb_policy_t _def_policy = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 2,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        }
    }
};

/* default policy for Details/Authorities pcr mapping */
static const tb_policy_t _def_policy_da = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 2,
    entries        : {
        {   /* mod 0 is extended to PCR 17 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 17 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 17,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        }
    }
};

/* current policy */
static const tb_policy_t* g_policy = &_def_policy;

/*
 * read_policy_from_tpm
 *
 * read policy from TPM NV into buffer
 *
 * policy_index_size is in/out
 */
static bool read_policy_from_tpm(tpm_nv_index_t index,
                void* policy_index, size_t *policy_index_size)
{
#define NV_READ_SEG_SIZE    256
    unsigned int offset = 0;
    unsigned int data_size = 0;
    uint32_t ret, index_size;

    if ( policy_index_size == NULL ) {
        printk(TBOOT_ERR"size is NULL\n");
        return false;
    }

    ret = tpm_get_nvindex_size(0, index, &index_size);
    if ( ret != TPM_SUCCESS )
        return false;

    if ( index_size > *policy_index_size ) {
        printk(TBOOT_WARN"policy in TPM NV %x was too big for buffer\n", index);
        index_size = *policy_index_size;
    }


    do {
        /* get data_size */
        if ( (index_size - offset) > NV_READ_SEG_SIZE )
            data_size = NV_READ_SEG_SIZE;
        else
            data_size = (uint32_t)(index_size - offset);

        /* read! */
        ret = tpm_nv_read_value(0, index, offset,
                                (uint8_t *)policy_index + offset, &data_size);
        if ( ret != TPM_SUCCESS || data_size == 0 )
            break;

        /* adjust offset */
        offset += data_size;
    } while ( offset < index_size );

    if ( offset == 0 && ret != TPM_SUCCESS ) {
        printk(TBOOT_ERR"Error: read TPM error: 0x%x from index %x.\n", ret, index);
        return false;
    }

    *policy_index_size = offset;

    return true;
}

/*
 * unwrap_lcp_policy
 *
 * unwrap custom element in lcp policy into tb policy
 * assume sinit has already verified lcp policy and lcp policy data.
 */
static bool unwrap_lcp_policy(void)
{
    void* lcp_base;
    uint32_t lcp_size;

    if ( txt_is_launched() ) {
        txt_heap_t *txt_heap = get_txt_heap();
        os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);

        lcp_base = (void *)(unsigned long)os_sinit_data->lcp_po_base;
        lcp_size = (uint32_t)os_sinit_data->lcp_po_size;
    }
    else {
        extern multiboot_info_t *g_mbi;
        if ( !find_lcp_module(g_mbi, &lcp_base, &lcp_size) )
            return false;
    }

    /* if lcp policy data version is 2+ */
    if ( memcmp((void *)lcp_base, LCP_POLICY_DATA_FILE_SIGNATURE,
             LCP_FILE_SIG_LENGTH) == 0 ) {
        lcp_policy_data_t *poldata = (lcp_policy_data_t *)lcp_base;
        lcp_policy_list_t *pollist = &poldata->policy_lists[0];

        for ( int i = 0; i < poldata->num_lists; i++ ) {
            lcp_policy_element_t *elt = pollist->policy_elements;
            uint32_t elts_size = 0;

            while ( elt ) {
                /* check element type */
                if ( elt->type == LCP_POLELT_TYPE_CUSTOM ) {
                    lcp_custom_element_t *custom =
                        (lcp_custom_element_t *)&elt->data;

                    /* check uuid in custom element */
                    if ( are_uuids_equal(&custom->uuid,
                             &((uuid_t)LCP_CUSTOM_ELEMENT_TBOOT_UUID)) ) {
                        memcpy(_policy_index_buf, &custom->data,
                            elt->size - sizeof(*elt) - sizeof(uuid_t));
                        return true; /* find tb policy */
                    }
                }

                elts_size += elt->size;
                if ( elts_size >= pollist->policy_elements_size )
                    break;

                elt = (void *)elt + elt->size;
            }
            pollist = (void *)pollist + get_policy_list_size(pollist);
        }
    }

    return false;
}

/*
 * set_policy
 *
 * load policy from TPM NV and validate it, else use default
 *
 */
tb_error_t set_policy(void)
{
    /* try to read tboot policy from TB_POLICY_INDEX in TPM NV */
    size_t policy_index_size = sizeof(_policy_index_buf);
    printk(TBOOT_INFO"reading Verified Launch Policy from TPM NV...\n");
    if ( read_policy_from_tpm(TB_POLICY_INDEX,
             _policy_index_buf, &policy_index_size) ) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        if ( verify_policy((tb_policy_t *)_policy_index_buf,
                 policy_index_size, true) ) {
            goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* tboot policy not found in TB_POLICY_INDEX, so see if it is wrapped
     * in a custom element in the PO policy; if so, SINIT will have verified
     * the policy and policy data for us; we just need to ensure the policy
     * type is LCP_POLTYPE_LIST (since we could have been give a policy data
     * file even though the policy was not a LIST */
    printk(TBOOT_INFO"reading Launch Control Policy from TPM NV...\n");
    if ( read_policy_from_tpm(INDEX_LCP_OWN,
             _policy_index_buf, &policy_index_size) ) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        /* assume lcp policy has been verified by sinit already */
        lcp_policy_t *pol = (lcp_policy_t *)_policy_index_buf;
        if ( pol->policy_type == LCP_POLTYPE_LIST && unwrap_lcp_policy() ) {
            if ( verify_policy((tb_policy_t *)_policy_index_buf,
                     calc_policy_size((tb_policy_t *)_policy_index_buf),
                     true) )
                goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* either no policy in TPM NV or policy is invalid, so use default */
    printk(TBOOT_WARN"failed to read policy from TPM NV, using default\n");
    g_policy = g_using_da ? &_def_policy_da : &_def_policy;
    policy_index_size = calc_policy_size(g_policy);

    /* sanity check; but if it fails something is really wrong */
    if ( !verify_policy(g_policy, policy_index_size, true) )
        return TB_ERR_FATAL;
    else
        return TB_ERR_POLICY_NOT_PRESENT;

policy_found:
    g_policy = (tb_policy_t *)_policy_index_buf;
    return TB_ERR_NONE;
}

/* hash current policy */
bool hash_policy(tb_hash_t *hash, uint8_t hash_alg)
{
    if ( hash == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    return hash_buffer((unsigned char *)g_policy, calc_policy_size(g_policy),
                       hash, hash_alg);
}

/* generate hash by hashing cmdline and module image */
static bool hash_module(tb_hash_t *hash, uint8_t hash_alg,
                        const char* cmdline, void *base,
                        size_t size)
{
    if ( hash == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    /* final hash is SHA-1( SHA-1(cmdline) | SHA-1(image) ) */
    /* where cmdline is first stripped of leading spaces, file name, then */
    /* any spaces until the next non-space char */
    /* (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "") */

    /* hash command line */
    if ( cmdline == NULL )
        cmdline = "";
    else
        cmdline = skip_filename(cmdline);
    if ( !hash_buffer((const unsigned char *)cmdline, strlen(cmdline), hash,
                      hash_alg) )
        return false;

    /* hash image and extend into cmdline hash */
    tb_hash_t img_hash;
    if ( !hash_buffer(base, size, &img_hash, hash_alg) )
        return false;
    if ( !extend_hash(hash, &img_hash, hash_alg) )
        return false;

    return true;
}

static bool is_hash_in_policy_entry(const tb_policy_entry_t *pol_entry,
                                    tb_hash_t *hash, uint8_t hash_alg)
{
    /* assumes policy entry has been validated */

    if ( pol_entry == NULL || hash == NULL) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    if ( pol_entry->hash_type == TB_HTYPE_ANY )
        return true;
    else if ( pol_entry->hash_type == TB_HTYPE_IMAGE ) {
        for ( int i = 0; i < pol_entry->num_hashes; i++ ) {
            if ( are_hashes_equal(get_policy_entry_hash(pol_entry, hash_alg,
                                                        i), hash, hash_alg) )
                return true;
        }
    }

    return false;
}

/*
 *
 * map policy type + error -> action
 *
 */
static tb_policy_action_t evaluate_error(tb_error_t error)
{
    tb_policy_action_t action = TB_POLACT_HALT;

    if ( error == TB_ERR_NONE )
        return TB_POLACT_CONTINUE;

    for ( unsigned int i = 0; i < ARRAY_SIZE(g_policy_map); i++ ) {
        if ( g_policy_map[i].policy_type == g_policy->policy_type ) {
            action = g_policy_map[i].default_action;
            for ( unsigned int j = 0;
                  j < ARRAY_SIZE(g_policy_map[i].exception_action_table);
                  j++ ) {
                if ( g_policy_map[i].exception_action_table[j].error ==
                     error )
                    action = g_policy_map[i].exception_action_table[j].action;
                if ( g_policy_map[i].exception_action_table[j].error ==
                     TB_ERR_NONE )
                    break;
            }
        }
    }

    return action;
}

/*
 * apply policy according to error happened.
 */
void apply_policy(tb_error_t error)
{
    tb_policy_action_t action;

    /* save the error to TPM NV */
    write_tb_error_code(error);

    if ( error != TB_ERR_NONE )
        print_tb_error_msg(error);

    action = evaluate_error(error);
    switch ( action ) {
        case TB_POLACT_CONTINUE:
            return;
        case TB_POLACT_UNMEASURED_LAUNCH:
            /* restore mtrr state saved before */
            restore_mtrrs(NULL);
            if ( s3_flag )
                s3_launch();
            else
                launch_kernel(false);
            break; /* if launch xen fails, do halt at the end */
        case TB_POLACT_HALT:
            break; /* do halt at the end */
        default:
            printk(TBOOT_ERR"Error: invalid policy action (%d)\n", action);
            /* do halt at the end */
    }

    _tboot_shared.shutdown_type = TB_SHUTDOWN_HALT;
    shutdown();
}

#define VL_ENTRIES(i)    g_pre_k_s3_state.vl_entries[i]
#define NUM_VL_ENTRIES   g_pre_k_s3_state.num_vl_entries

/*
 * verify modules against Verified Launch policy and save hash
 * if pol_entry is NULL, assume it is for module 0, which gets extended
 * to PCR 18
 */
static tb_error_t verify_module(module_t *module, tb_policy_entry_t *pol_entry,
                                uint8_t hash_alg)
{
    /* assumes module is valid */

    void *base = (void *)module->mod_start;
    size_t size = module->mod_end - module->mod_start;
    char *cmdline = (char *)module->string;

    if ( pol_entry != NULL ) {
        /* chunk the command line into 80 byte chunks */
#define CHUNK_SIZE 80
        int      cmdlen = strlen(cmdline);
        char    *cptr = cmdline;
        char     cmdchunk[CHUNK_SIZE+1];
        printk(TBOOT_INFO"verifying module \"");
        while (cmdlen > 0) {
            strncpy(cmdchunk, cptr, CHUNK_SIZE);
            cmdchunk[CHUNK_SIZE] = 0;
            printk(TBOOT_INFO"\n%s", cmdchunk);
            cmdlen -= CHUNK_SIZE;
            cptr += CHUNK_SIZE;
        }
        printk(TBOOT_INFO"\"...\n");
    }

    tb_hash_t hash;
    if ( !hash_module(&hash, TB_HALG_SHA1, cmdline, base, size) ) {
        printk(TBOOT_ERR"\t hash cannot be generated.\n");
        return TB_ERR_MODULE_VERIFICATION_FAILED;
    }

    /* add new hash to list (unless it doesn't get put in a PCR)
       we'll just drop it if the list is full, but that will mean S3 resume
       PCRs won't match pre-S3
       NULL pol_entry means this is module 0 which is extended to PCR 18 */
    if ( NUM_VL_ENTRIES >= MAX_VL_HASHES )
        printk(TBOOT_WARN"\t too many hashes to save\n");
    else if ( pol_entry == NULL || pol_entry->pcr != TB_POL_PCR_NONE ) {
        uint8_t pcr = (pol_entry == NULL ) ?
                          (g_using_da ? 17 : 18) : pol_entry->pcr;
        VL_ENTRIES(NUM_VL_ENTRIES).pcr = pcr;
        VL_ENTRIES(NUM_VL_ENTRIES++).hash = hash;
    }

    if ( pol_entry != NULL &&
         !is_hash_in_policy_entry(pol_entry, &hash, hash_alg) ) {
        printk(TBOOT_ERR"\t verification failed\n");
        return TB_ERR_MODULE_VERIFICATION_FAILED;
    }

    if ( pol_entry != NULL ) {
        printk(TBOOT_DETA"\t OK : "); print_hash(&hash, TB_HALG_SHA1);
    }
    return TB_ERR_NONE;
}

void verify_all_modules(multiboot_info_t *mbi)
{
    /* assumes mbi is valid */

    /* add entry for policy control field and (optionally) policy */
    /* hash will be <policy control field (4bytes)> | <hash policy> */
    /* where <hash policy> will be 0s if TB_POLCTL_EXTEND_PCR17 is clear */
    static uint8_t buf[sizeof(tb_hash_t) + sizeof(g_policy->policy_control)];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &g_policy->policy_control, sizeof(g_policy->policy_control));
    if ( g_policy->policy_control & TB_POLCTL_EXTEND_PCR17 ) {
        if ( !hash_policy((tb_hash_t *)&buf[sizeof(g_policy->policy_control)],
                          TB_HALG_SHA1) ) {
            printk(TBOOT_ERR"policy hash failed\n");
            apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
        }
    }
    if ( !hash_buffer(buf, get_hash_size(TB_HALG_SHA1) +
                           sizeof(g_policy->policy_control),
                      &VL_ENTRIES(NUM_VL_ENTRIES).hash, TB_HALG_SHA1) )
        apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
    VL_ENTRIES(NUM_VL_ENTRIES++).pcr = 17;
    if ( g_using_da ) {
        /* copying hash of policy_control into PCR 18 */
        if ( NUM_VL_ENTRIES >= MAX_VL_HASHES )
            printk(TBOOT_ERR"\t too many hashes to save for DA\n");
        else {
            VL_ENTRIES(NUM_VL_ENTRIES).hash = VL_ENTRIES(NUM_VL_ENTRIES-1).hash;
            VL_ENTRIES(NUM_VL_ENTRIES++).pcr = 18;
        }
    }

    /* module 0 is always extended to PCR 18, so add entry for it */
    apply_policy(verify_module(get_module(mbi, 0), NULL, g_policy->hash_alg));

    /* now verify each module and add its hash */
    for ( unsigned int i = 0; i < mbi->mods_count; i++ ) {
        module_t *module = get_module(mbi, i);
        tb_policy_entry_t *pol_entry = find_policy_entry(g_policy, i);
        if ( module == NULL ) {
            printk(TBOOT_ERR"missing module entry %u\n", i);
            apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
        }
        else if ( pol_entry == NULL ) {
            printk(TBOOT_ERR"policy entry for module %u not found\n", i);
            apply_policy(TB_ERR_MODULES_NOT_IN_POLICY);
        }
        else
            apply_policy(verify_module(module, pol_entry, g_policy->hash_alg));
    }

    printk(TBOOT_INFO"all modules are verified\n");
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
