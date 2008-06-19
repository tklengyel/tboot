/*
 * policy.c: support functions for tboot verification launch
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

#include <config.h>
#include <stdarg.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string2.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <multiboot.h>
#include <hash.h>
#include <tb_error.h>
#include <tb_policy.h>
#include <txt/config_regs.h>
#include <tpm.h>
#include <elf.h>
#include <tboot.h>

extern void shutdown(void);
extern void s3_launch(void);

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

extern multiboot_info_t *g_mbi;
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
    { TB_POLTYPE_CONT_NON_FATAL, TB_POLACT_CONTINUE,
      {
          {TB_ERR_FATAL,                     TB_POLACT_HALT},
          {TB_ERR_TPM_NOT_READY,             TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SMX_NOT_SUPPORTED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VMX_NOT_SUPPORTED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_TXT_NOT_SUPPORTED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SINIT_NOT_PRESENT,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_ACMOD_VERIFY_FAILED,       TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_NONE,                      TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_CONT_VERIFY_FAIL, TB_POLACT_HALT,
      {
          {TB_ERR_POLICY_VMM_VERIFY_FAILED,  TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_DOM0_VERIFY_FAILED, TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_NOT_PRESENT,        TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_INVALID,            TB_POLACT_CONTINUE},
          {TB_ERR_NONE,                      TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_HALT, TB_POLACT_HALT,
      {
          {TB_ERR_NONE,                      TB_POLACT_CONTINUE},
      }
    },
};

/* tb_policy buffer */
#define MAX_TB_POL_INDEX_SIZE       sizeof(tb_policy_index_t) + \
                                    8 * (sizeof(tb_policy_t) +  \
                                    6 * sizeof(tb_hash_t))
static unsigned char _policy_index_buf[MAX_TB_POL_INDEX_SIZE];

/* default policy */
static const tb_policy_index_t _def_policy = {
    version       : 0x01,
    policy_type   : DEF_POLICY_TYPE,
    num_policies  : 2,
    policies      : {
        {        /* Xen/VMM */
            uuid        : TBPOL_VMM_UUID,
            hash_alg    : TB_HALG_SHA1,
            hash_type   : TB_HTYPE_ANY,
            num_hashes  : 0,
        },
        {        /* dom0 + initrd */
            uuid        : TBPOL_DOM0_UUID,
            hash_alg    : TB_HALG_SHA1,
            hash_type   : TB_HTYPE_ANY,
            num_hashes  : 0,
        },
    }
};

/* current policy */
static const tb_policy_index_t* g_policy_index = &_def_policy;

/* hashes that are used to restore DRTM PCRs in S3 resume */
tcb_hashes_t g_tcb_hashes;

static void display_tcb_hashes(void)
{
    printk("g_tcb_hashes:\n");
    printk("\t vmm: "); print_hash(&g_tcb_hashes.vmm, TB_HALG_SHA1);
    printk("\t dom0: "); print_hash(&g_tcb_hashes.dom0, TB_HALG_SHA1);
    printk("\t policy: "); print_hash(&g_tcb_hashes.policy, TB_HALG_SHA1);
}

/*
 * verify policy
 */
static bool verify_policy(const tb_policy_index_t *tb_policy_index, int size)
{
    const tb_policy_t *policy;

    printk("tb_policy_index:\n");

    if ( tb_policy_index == NULL ) {
        printk("tb_policy_index pointer is NULL\n");
        return false;
    }

    if ( size < sizeof(tb_policy_index_t) ) {
        printk("size of policy is too small (%d)\n", size);
        return false;
    }

    if ( tb_policy_index->version != 0x01 ) {
        printk("unsupported version (%d)\n", tb_policy_index->version);
        return false;
    }
    printk("\t version = %d\n", tb_policy_index->version);

    if ( tb_policy_index->policy_type >= TB_POLTYPE_MAX ) {
        printk("unsupported policy_type (%d)\n", tb_policy_index->policy_type);
        return false;
    }
    printk("\t policy_type = %d\n", tb_policy_index->policy_type);

    printk("\t num_policies = %d\n", tb_policy_index->num_policies);

    policy = tb_policy_index->policies;
    for ( int i = 0; i < tb_policy_index->num_policies; i++ ) {
        /* check header of policy */
        if ( ((void *)policy - (void *)tb_policy_index + sizeof(tb_policy_t)) >
             size ) {
            printk("size of policy is too small (%d)\n", size);
            return false;
        }

        printk("\t policy[%d]:\n", i);

        printk("\t\t uuid = "); print_uuid(&(policy->uuid)); printk("\n");

        if ( policy->hash_alg != TB_HALG_SHA1 ) {
            printk("unsupported hash_alg (%d)\n", policy->hash_alg);
            return false;
        }
        printk("\t\t hash_alg = %d\n", policy->hash_alg);

        if ( policy->hash_type > TB_HTYPE_HASHONLY ) {
            printk("unsupported hash_type (%d)\n", policy->hash_type);
            return false;
        }
        printk("\t\t hash_type = %d\n", policy->hash_type);

        printk("\t\t num_hashes = %d\n", policy->num_hashes);

        /* check all of policy */
        if ( ((void *)policy - (void *)tb_policy_index + sizeof(tb_policy_t) +
              policy->num_hashes * sizeof(tb_hash_t)) >
             size ) {
            printk("size of policy is too small (%d)\n", size);
            return false;
        }

        for ( int j = 0; j < policy->num_hashes; j++ ) {
            printk("\t\t hashes[%d] = ", j);
            print_hash(&(policy->hashes[j]), policy->hash_alg);
        }

        policy = (void *)policy + sizeof(tb_policy_t) +
            policy->num_hashes * sizeof(tb_hash_t);
    }

    return true;
}

/*
 * get_policy
 *
 * get the policy entry
 *
 */
static tb_policy_t* get_policy(const tb_policy_index_t *tb_policy_index, int i)
{
    tb_policy_t* policy;
    int j;

    /* assumes tb_policy_index has already been validated */

    if ( tb_policy_index == NULL ) {
        printk("Error: tb_policy_index pointer is zero.\n");
        return NULL;
    }

    if ( i < 0 || i > tb_policy_index->num_policies ) {
        printk("Error: position is not correct.\n");
        return NULL;
    }

    policy = (tb_policy_t *)tb_policy_index->policies;
    for ( j = 0; j < i; j++ )
        policy = (void *)policy + sizeof(tb_policy_t) +
            policy->num_hashes * sizeof(tb_hash_t);

    return policy;
}

#define NV_READ_SEG_SIZE    256
/*
 * read_tb_policy
 *
 * read policy from TPM into buffer (TB_TCB_POLICY_IDX)
 *
 * policy_index_size is in/out
 */
static bool read_policy(void* policy_index, unsigned int *policy_index_size)
{
    int offset = 0;
    unsigned int data_size = 0;
    uint32_t ret, index_size;

    if ( policy_index_size == NULL ) {
        printk("size is NULL\n");
        return false;
    }

    ret = tpm_get_nvindex_size(0, TB_TCB_POLICY_IDX, &index_size);
    if ( ret != TPM_SUCCESS ) {
        printk("failed to get actual policy size in TPM NV\n");
        return false;
    }

    if ( index_size > *policy_index_size ) {
        printk("policy in TPM NV was too big for buffer\n");
        index_size = *policy_index_size;
    }


    do {
        /* get data_size */
        if ( (index_size - offset) > NV_READ_SEG_SIZE )
            data_size = NV_READ_SEG_SIZE;
        else
            data_size = (uint32_t)(index_size - offset);

        /* read! */
        ret = tpm_nv_read_value(0, TB_TCB_POLICY_IDX, offset,
                                (uint8_t *)policy_index + offset, &data_size);
        if ( ret != TPM_SUCCESS || data_size == 0 )
            break;

        /* adjust offset */
        offset += data_size;
    } while ( offset < index_size );

    if ( offset == 0 && ret != TPM_SUCCESS ) {
        printk("Error: read TPM error: 0x%x.\n", ret);
        return false;
    }

    *policy_index_size = offset;

    return true;
}

/*
 * load_policy
 *
 * load policy from TPM into global buffer
 *
 */
tb_error_t load_policy(void)
{
    tb_error_t err = TB_ERR_FATAL;
    unsigned int policy_index_size = MAX_TB_POL_INDEX_SIZE;

    if ( read_policy(_policy_index_buf, &policy_index_size) ) {
        if ( !verify_policy((tb_policy_index_t *)_policy_index_buf,
                            policy_index_size) )
            err = TB_ERR_POLICY_INVALID;
        else {
            g_policy_index = (tb_policy_index_t *)_policy_index_buf;
            printk("read TCB policy (%u) from TPM NV\n", policy_index_size);
            err = TB_ERR_NONE;
        }
    }

    if ( err != TB_ERR_NONE ) {    /* use default policy */
        printk("failed to read policy from TPM NV, using default\n");
        g_policy_index = &_def_policy;
        policy_index_size = sizeof(_def_policy);
        /* tb_policy_index_t has empty array, which isn't counted in size */
        /* so add size of each policy */
        for ( int i = 0; i < _def_policy.num_policies; i++ ) {
            policy_index_size += sizeof(_def_policy.policies[i]);
            /* and each policy has empty hash array, so count those */
            policy_index_size += _def_policy.policies[i].num_hashes *
                sizeof(_def_policy.policies[i].hashes[0]);
        }
        /* sanity check; but if it fails something is really wrong */
        if ( !verify_policy(g_policy_index, policy_index_size) )
            err = TB_ERR_FATAL;
        else
            err = TB_ERR_POLICY_NOT_PRESENT;
    }

    return err;
}

/*
 * hash_images
 *
 * hash images given hash algorithm:
 *        if one image, hash it;
 *        if more than one image, hash-extend them
 *
 */
static bool hash_images(tb_hash_t *hash, uint8_t hash_alg,
                        int va_list_len, va_list ap)
{
    uint32_t base, size;
    tb_hash_t imagehash;

    memset((void *)&imagehash, 0, sizeof(tb_hash_t));

    if (( hash == NULL ) || ( va_list_len <= 0 )) {
        printk("Error: input parameter is wrong.\n");
        return false;
    }

    for ( int i = 0; i < va_list_len; i++ ) {
        /* get image base address */
        base = va_arg(ap, uint32_t);
        /* get image size */
        size = va_arg(ap, uint32_t);

        /* hash image */
        printk("hash of image @ 0x%08x is...\n    ", base);
        if ( !hash_buffer((unsigned char *)base, size, &imagehash, hash_alg) )
            return false;
        print_hash(&imagehash, hash_alg);

        /* multiple images need to be "extended" together: */
        /* final = SHA-1(final || image) */
        printk("cummulative hash is...\n    ");
        if ( !extend_hash(hash, &imagehash, hash_alg) )
            return false;
        print_hash(hash, hash_alg);
    }

    return true;
}

static bool is_hash_in_policy(const tb_policy_t *policy, const tb_hash_t *hash)
{
    if (( policy == NULL ) || ( hash == NULL )) {
        printk("Error: input pointer is zero.\n");
        return false;
    }

    for ( int i = 0; i < policy->num_hashes; i++ ) {
        if ( are_hashes_equal(&(policy->hashes[i]), hash, policy->hash_alg) )
            return true;
    }
    return false;
}

/* generate hash by hashing cmdline and modules */
static bool generate_hash(tb_hash_t *m_hash, uint8_t hash_alg, 
                          const unsigned char* cmdline, int va_list_len, ...)
{
    va_list ap;
    tb_hash_t hash;

    /* assumes policy has been validated */

    if (( m_hash == NULL ) || ( va_list_len <= 0 )) {
        printk("Error: input parameter is wrong.\n");
        return false;
    }

    /* hash command line */
    printk("hash of command line \"%s\" is...\n    ", cmdline);
    if ( !hash_buffer(cmdline, strlen((char *)cmdline), &hash,
                      hash_alg) )
        return false;
    print_hash(&hash, hash_alg);

    /* hash images */
    va_start(ap, va_list_len);
    if ( !hash_images(&hash, hash_alg, va_list_len, ap) )
        return false;
    va_end(ap);

    *m_hash = hash;
    return true;
}

static bool evaluate_policy(tb_policy_t *policy, tb_hash_t *m_hash)
{
    /* assumes policy has been validated */

    if ( policy == NULL || m_hash == NULL) {
        printk("Error: input parameter is wrong.\n");
        return false;
    }

    if ( policy->hash_type == TB_HTYPE_ANY )
        return true;
    else if ( policy->hash_type == TB_HTYPE_HASHONLY )
        return is_hash_in_policy(policy, m_hash);

    return false;
}

static tb_policy_t* find_policy_by_uuid(const tb_policy_index_t *policy_index,
                                        const uuid_t *uuid)
{
    tb_policy_t *policy;

    for ( int i = 0; i < policy_index->num_policies; i++ ) {
        /* find the policy */
        policy = get_policy(policy_index, i);
        if ( policy == NULL )
            return NULL;

        /* check uuid */
        if ( are_uuids_equal(&(policy->uuid), uuid) )
            return policy;
    }

    return NULL;
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

    for ( int i = 0; i < ARRAY_SIZE(g_policy_map); i++ ) {
        if ( g_policy_map[i].policy_type == g_policy_index->policy_type ) {
            action = g_policy_map[i].default_action;
            for ( int j = 0;
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
            if ( s3_flag )
                s3_launch();
            else
                launch_xen(g_mbi, false);
            break; /* if launch xen fails, do halt at the end */
        case TB_POLACT_HALT:
            break; /* do halt at the end */
        default:
            printk("Error: invalid policy action (%d)\n", action);
            /* do halt at the end */
    }

    _tboot_shared.shutdown_type = TB_SHUTDOWN_HALT;
    shutdown();
}

static unsigned int calc_tcb_policy_size(void)
{
    unsigned int size = sizeof(*g_policy_index);

    /* tb_policy_index_t has empty array, which isn't counted in size */
    /* so add size of each policy */
    const tb_policy_t *policy = g_policy_index->policies;
    for ( int i = 0; i < g_policy_index->num_policies; i++ ) {
        size += sizeof(*policy);
        /* and each policy has empty hash array, so count those */
        size += policy->num_hashes * sizeof(policy->hashes[0]);
        policy = (void *)policy + sizeof(tb_policy_t) +
            policy->num_hashes * sizeof(tb_hash_t);
    }

    return size;
}

/*
 * verify modules against TCB policy
 */
static tb_error_t evaluate_vmm(multiboot_info_t *mbi)
{
    tb_policy_t *policy;

    /*
     * verify Xen/VMM
     */

    /* generate hash for VMM */
    if ( mbi != NULL ) {
        module_t *m;
        unsigned char *cmdline;
        uint32_t vmm_base, vmm_size;

        memset(&g_tcb_hashes.vmm, 0, sizeof(g_tcb_hashes.vmm));

        /* get VMM module info */
        m = get_module(mbi, 0);
        if ( m == NULL )
            return TB_ERR_FATAL;
        vmm_base = m->mod_start;
        vmm_size = m->mod_end - m->mod_start;
        cmdline = (unsigned char *)m->string;

        if ( !generate_hash(&g_tcb_hashes.vmm, TB_HALG_SHA1, cmdline, 1, 
                            vmm_base, vmm_size) ) {
            printk("VMM hash can NOT be generated.\n");
            early_vga_printk("The installed components do not match the "
                             "verified launch policy.\n");
            return TB_ERR_POLICY_VMM_VERIFY_FAILED;
        }
    }

    /* get VMM policy */
    policy = find_policy_by_uuid(g_policy_index, &((uuid_t)TBPOL_VMM_UUID));
    if ( policy == NULL ) {
        printk("no VMM policy\n");
        return TB_ERR_POLICY_NOT_PRESENT;
    }

    /* verify */
    printk("verifying VMM policy...\n");
    if ( !evaluate_policy(policy, &g_tcb_hashes.vmm) ) {
        printk("VMM is NOT verified.\n");
        early_vga_printk("The installed components do not match the "
                         "verified launch policy.\n");
        return TB_ERR_POLICY_VMM_VERIFY_FAILED;
    }

    printk("VMM is verified.\n");
    return TB_ERR_NONE;
}

static tb_error_t evaluate_dom0(multiboot_info_t *mbi)
{
    tb_policy_t *policy;

    /*
     * verify dom0
     */

    /* generate hash for dom0 */
    if ( mbi != NULL ) {
        module_t *m;
        unsigned char *cmdline;
        uint32_t vmlinuz_base, vmlinuz_size;
        uint32_t initrd_base, initrd_size;

        memset(&g_tcb_hashes.dom0, 0, sizeof(g_tcb_hashes.dom0));

        /* get vmlinuz module info */
        m = get_module(mbi, 1);
        if ( m == NULL )
            return TB_ERR_FATAL;
        vmlinuz_base = m->mod_start;
        vmlinuz_size = m->mod_end - m->mod_start;
        cmdline = (unsigned char *)m->string;

        /* get initrd module info */
        m = get_module(mbi, 2);
        if ( m == NULL )
            return TB_ERR_GENERIC;
        initrd_base = m->mod_start;
        initrd_size = m->mod_end - m->mod_start;
        /* initrd cmd line is irrelevant */

        if ( !generate_hash(&g_tcb_hashes.dom0, TB_HALG_SHA1, cmdline, 2, 
                             vmlinuz_base, vmlinuz_size,
                             initrd_base, initrd_size) ) {
            printk("dom0 hash can NOT be generated.\n");
            early_vga_printk("The installed components do not match the "
                             "verified launch policy.\n");
            return TB_ERR_POLICY_DOM0_VERIFY_FAILED;
        }
    }

    /* get dom0 policy */
    policy = find_policy_by_uuid(g_policy_index, &((uuid_t)TBPOL_DOM0_UUID));
    if ( policy == NULL ) {
        printk("no dom0 policy\n");
        return TB_ERR_POLICY_NOT_PRESENT;
    }

    /* verify */
    printk("verifying dom0 policy...\n");
    if ( !evaluate_policy(policy, &g_tcb_hashes.dom0)) {
        printk("dom0 is NOT verified.\n");
        early_vga_printk("The installed components do not match the "
                         "verified launch policy.\n");
        return TB_ERR_POLICY_DOM0_VERIFY_FAILED;
    }

    printk("dom0 is verified.\n");
    return TB_ERR_NONE;
} 

void evaluate_all_policies(multiboot_info_t *mbi)
{
    apply_policy(evaluate_vmm(mbi));
    apply_policy(evaluate_dom0(mbi));
    
    /*
     * ensure no more modules
     */
    if ( get_module(mbi, 3) != NULL ) {
        printk("there are additional modules not in policy.\n");
        apply_policy(TB_ERR_POLICY_MODULES_NOT_IN_POLICY);
    }
    
    /* 
     * generate hash of tcb policy
     */
    hash_buffer((unsigned char *)g_policy_index, calc_tcb_policy_size(),
         &g_tcb_hashes.policy, TB_HALG_SHA1);

    display_tcb_hashes();
}

void re_evaluate_all_policies(void)
{
    apply_policy(evaluate_vmm(NULL));
    apply_policy(evaluate_dom0(NULL));
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
