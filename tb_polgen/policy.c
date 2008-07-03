/*
 * policy.c: policy support functions
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
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/uuid.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

#define MAX_TB_POL_HASHES      3
#define MAX_TB_POLICIES        6

/*
 * internal policy structures to facilitate operations
 */

typedef struct {
    uuid_t       uuid;
    uint8_t      hash_alg;            /* TB_HALG_* */
    uint8_t      hash_type;           /* TB_HTYPE_* */
    uint8_t      num_hashes;
    tb_hash_t    hashes[MAX_TB_POL_HASHES];
} _policy_t;

typedef struct {
    uint8_t        version;      /* applies to this and tb_policy_t */
    uint8_t        policy_type;  /* TB_POLTYPE_* */
    uint8_t        num_policies;
    _policy_t      policies[MAX_TB_POLICIES];
} _policy_index_t;


#define MAX_TB_POL_INDEX_SIZE       sizeof(tb_policy_index_t) + \
                                    MAX_TB_POLICIES * (sizeof(tb_policy_t) +  \
                                    MAX_TB_POLICIES * MAX_TB_POL_HASHES * \
                                                       sizeof(tb_hash_t))

/* tb_policy_index_t buffer for data read/written from/to policy file */
static unsigned char _tb_policy_index_buf[MAX_TB_POL_INDEX_SIZE];

static _policy_index_t g_policy_index;


static bool verify_policy(const unsigned char *policy_index_buf, int size)
{
    const tb_policy_index_t *policy_index =
        (const tb_policy_index_t *)policy_index_buf;
    const tb_policy_t *policy;
    int i, j;

    info_msg("policy_index:\n");

    if ( policy_index_buf == NULL ) {
        info_msg("tb_policy_index pointer is NULL\n");
        return false;
    }

    if ( size < sizeof(tb_policy_index_t) ) {
        info_msg("size of policy is too small (%d)\n", size);
        return false;
    }

    if ( policy_index->version != 0x01 ) {
        info_msg("unsupported version (%d)\n", policy_index->version);
        return false;
    }
    info_msg("\t version = %d\n", policy_index->version);

    if ( policy_index->policy_type >= TB_POLTYPE_MAX ) {
        info_msg("unsupported policy_type (%d)\n", policy_index->policy_type);
        return false;
    }
    info_msg("\t policy_type = %d\n", policy_index->policy_type);

    info_msg("\t num_policies = %d\n", policy_index->num_policies);

    policy = policy_index->policies;
    for ( i = 0; i < policy_index->num_policies; i++ ) {
        /* check header of policy */
        if ( ((void *)policy - (void *)policy_index + sizeof(tb_policy_t)) >
             size ) {
            info_msg("size of policy is too small (%d)\n", size);
            return false;
        }

        info_msg("\t policy[%d]:\n", i);

        info_msg("\t\t uuid = "); if ( verbose ) print_uuid(&(policy->uuid));
        info_msg("\n");

        if ( policy->hash_alg != TB_HALG_SHA1 ) {
            info_msg("unsupported hash_alg (%d)\n", policy->hash_alg);
            return false;
        }
        info_msg("\t\t hash_alg = %d\n", policy->hash_alg);

        if ( policy->hash_type > TB_HTYPE_HASHONLY ) {
            info_msg("unsupported hash_type (%d)\n", policy->hash_type);
            return false;
        }
        info_msg("\t\t hash_type = %d\n", policy->hash_type);

        info_msg("\t\t num_hashes = %d\n", policy->num_hashes);

        /* check all of policy */
        if ( ((void *)policy - (void *)policy_index + sizeof(tb_policy_t) +
              policy->num_hashes * sizeof(tb_hash_t)) >
             size ) {
            info_msg("size of policy is too small (%d)\n", size);
            return false;
        }

        for ( j = 0; j < policy->num_hashes; j++ ) {
            info_msg("\t\t hashes[%d] = ", j);
            if ( verbose ) print_hash(&(policy->hashes[j]), policy->hash_alg);
        }

        policy = (void *)policy + sizeof(tb_policy_t) +
            policy->num_hashes * sizeof(tb_hash_t);
    }

    return true;
}

bool read_policy_file(const char *policy_filename)
{
    FILE *f;
    size_t read_cnt;
    const tb_policy_index_t *tb_policy_index =
        (const tb_policy_index_t *)_tb_policy_index_buf;
    const tb_policy_t *tb_policy;
    _policy_t *policy;
    int i, j;

    f = fopen(policy_filename, "r");
    if ( f == NULL ) {
        info_msg("fopen failed, errno %s\n", strerror(errno));
        return false;
    }

    /* clear for good measure */
    memset(_tb_policy_index_buf, sizeof(_tb_policy_index_buf), 0);

    read_cnt = fread(_tb_policy_index_buf, 1, sizeof(_tb_policy_index_buf), f);
    if ( !verify_policy(_tb_policy_index_buf, read_cnt) ) {
        info_msg("fread failed, errno %s\n", strerror(errno));
        error_msg("Policy file %s is corrupt\n", policy_filename);
        return false;
    }

    /*
     * de-serialize to internal data struct
     */
    memset(&g_policy_index, 0, sizeof(g_policy_index));

    g_policy_index.version = tb_policy_index->version;
    g_policy_index.policy_type = tb_policy_index->policy_type;
    g_policy_index.num_policies = tb_policy_index->num_policies;
    
    tb_policy = tb_policy_index->policies;
    for ( i = 0; i < g_policy_index.num_policies; i++ ) {
        policy = &(g_policy_index.policies[i]);

        policy->uuid = tb_policy->uuid;
        policy->hash_alg = tb_policy->hash_alg;
        policy->hash_type = tb_policy->hash_type;
        policy->num_hashes = tb_policy->num_hashes;
        for ( j = 0; j < policy->num_hashes; j++ )
            copy_hash(&policy->hashes[j], &tb_policy->hashes[j], TB_HALG_SHA1);

        tb_policy = (void *)tb_policy + sizeof(tb_policy_t) +
            policy->num_hashes * sizeof(tb_hash_t);
    }

    return true;
}

bool write_policy_file(const char *policy_filename)
{
    FILE *f;
    size_t write_cnt;
    tb_policy_index_t *tb_policy_index =
        (tb_policy_index_t *)_tb_policy_index_buf;
    tb_policy_t *tb_policy;
    _policy_t *policy;
    int i, j;

    /*
     * serialize from internal data struct
     */
    memset(_tb_policy_index_buf, sizeof(_tb_policy_index_buf), 0);

    tb_policy_index->version = g_policy_index.version;
    tb_policy_index->policy_type = g_policy_index.policy_type;
    tb_policy_index->num_policies = g_policy_index.num_policies;

    tb_policy = tb_policy_index->policies;
    for ( i = 0; i < g_policy_index.num_policies; i++ ) {
        policy = &(g_policy_index.policies[i]);

        tb_policy->uuid = policy->uuid;
        tb_policy->hash_alg = policy->hash_alg;
        tb_policy->hash_type = policy->hash_type;
        tb_policy->num_hashes = policy->num_hashes;
        for ( j = 0; j < policy->num_hashes; j++ )
            copy_hash(&tb_policy->hashes[j], &policy->hashes[j], TB_HALG_SHA1);

        tb_policy = (void *)tb_policy + sizeof(tb_policy_t) +
            tb_policy->num_hashes * sizeof(tb_hash_t);
    }

    /*
     * write serialized data to policy file
     */

    f = fopen(policy_filename, "w");
    if ( f == NULL ) {
        info_msg("fopen failed, errno %s\n", strerror(errno));
        return false;
    }

    /* write fixed-size part */
    write_cnt = fwrite(tb_policy_index, 1, sizeof(*tb_policy_index), f);
    if ( write_cnt != sizeof(*tb_policy_index) ) {
        info_msg("error writing policy_index, errno %s\n", strerror(errno));
        goto error;
    }
    tb_policy = tb_policy_index->policies;
    for ( i = 0; i < tb_policy_index->num_policies; i++ ) {
        /* write fixed-size part */
        write_cnt = fwrite(tb_policy, 1, sizeof(*tb_policy), f);
        if ( write_cnt != sizeof(*tb_policy) ) {
            info_msg("error writing policy, errno %s\n", strerror(errno));
            goto error;
        }

        /* write hashes */
        write_cnt = fwrite(tb_policy->hashes, 1,
                           tb_policy->num_hashes *
                           sizeof(tb_policy->hashes[0]), f);
        if ( write_cnt != tb_policy->num_hashes *
             sizeof(tb_policy->hashes[0]) ) {
            info_msg("error writing policy hashes, errno %s\n",
                     strerror(errno));
            goto error;
        }

        tb_policy = (void *)tb_policy + sizeof(tb_policy_t) +
            tb_policy->num_hashes * sizeof(tb_hash_t);
    }

    fclose(f);

    return true;

 error:
    fclose(f);
    return false;
}

static char *policy_type_to_string(tb_policy_type_t policy_type)
{
    static char buf[64];

    switch ( policy_type ) {
        case TB_POLTYPE_CONT_NON_FATAL:
            return "TB_POLTYPE_CONT_NON_FATAL";
        case TB_POLTYPE_CONT_VERIFY_FAIL:
            return "TB_POLTYPE_CONT_VERIFY_FAIL";
        case TB_POLTYPE_HALT:
            return "TB_POLTYPE_HALT";
        default:
            snprintf(buf, sizeof(buf), "unsupported (%d)", policy_type);
            return buf;
    }
}

static char *hash_type_to_string(tb_hash_type_t hash_type)
{
    static char buf[64];

    switch ( hash_type ) {
        case TB_HTYPE_ANY:
            return "TB_HTYPE_ANY";
        case TB_HTYPE_HASHONLY:
            return "TB_HTYPE_HASHONLY";
        default:
            snprintf(buf, sizeof(buf), "unsupported (%d)", hash_type);
            return buf;
    }
}

void display_policy(void)
{
    int i, j;

    /* assumes policy_index has already been validated */

    printf("policy_index:\n");
    printf("\t version = %d\n", g_policy_index.version);
    printf("\t policy_type = %s\n",
           policy_type_to_string(g_policy_index.policy_type));
    printf("\t num_policies = %d\n", g_policy_index.num_policies);

    for ( i = 0; i < g_policy_index.num_policies; i++ ) {
        _policy_t *policy = &(g_policy_index.policies[i]);

        printf("\t policy[%d]:\n", i);
        printf("\t\t uuid = ");
        if ( are_uuids_equal(&policy->uuid, &((uuid_t)TBPOL_VMM_UUID)) )
            printf("VMM\n");
        else if ( are_uuids_equal(&policy->uuid, &((uuid_t)TBPOL_DOM0_UUID)) )
            printf("DOM0\n");
        else {
            print_uuid(&(policy->uuid)); printf("\n");
        }
        printf("\t\t hash_alg = %s\n", hash_alg_to_string(policy->hash_alg));
        printf("\t\t hash_type = %s\n",
               hash_type_to_string(policy->hash_type));
        printf("\t\t num_hashes = %d\n", policy->num_hashes);
        for ( j = 0; j < policy->num_hashes; j++ ) {
            printf("\t\t hashes[%d] = ", j);
            print_hash(&(policy->hashes[j]), policy->hash_alg);
        }
    }
}

void modify_policy_index(tb_policy_type_t policy_type)
{
    /* current version is 1 */
    g_policy_index.version = 1;

    if ( policy_type != -1 )
        g_policy_index.policy_type = policy_type;
}

bool replace_policy(const uuid_t *uuid, tb_hash_type_t hash_type,
                    const tb_hash_t *hash)
{
    _policy_t *policy = NULL;
    int i;

    /* find any existing policy with same UUID */
    for ( i = 0; i < g_policy_index.num_policies; i++ ) {
        policy = &(g_policy_index.policies[i]);
        if ( are_uuids_equal(&policy->uuid, uuid) )
            break;
    }

    /* if none found, then need to add at first empty slot */
    /* which will be current value of i */
    if ( i == g_policy_index.num_policies ) {
        if ( g_policy_index.num_policies >= MAX_TB_POLICIES )
            return false;
        info_msg("adding a new policy\n");
        policy = &(g_policy_index.policies[i]);
        policy->uuid = *uuid;
        policy->hash_alg = TB_HALG_SHA1;
        g_policy_index.num_policies++;
    }
    else
        info_msg("updating existing policy\n");

    policy->hash_type = hash_type;
    if ( hash_type == TB_HTYPE_ANY )
        policy->num_hashes = 0;
    else {
        policy->num_hashes = 1;
        copy_hash(&policy->hashes[0], hash, TB_HALG_SHA1);
    }

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
