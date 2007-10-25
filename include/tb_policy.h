/*
 * tb_policy.h: structions and definitions for tboot policies
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

#ifndef __TB_POLICY_H__
#define __TB_POLICY_H__

/*
 * policy types
 */
typedef enum {
    TB_POLTYPE_CONT_NON_FATAL,     /* ignore all non-fatal errors and */
                                   /*                 halt otherwise */
    TB_POLTYPE_CONT_VERIFY_FAIL,   /* ignore verification errors and */
                                   /*                 halt otherwise */
    TB_POLTYPE_HALT,               /* halt on any errors */
    TB_POLTYPE_MAX
} tb_policy_type_t;

#define DEF_POLICY_TYPE    TB_POLTYPE_CONT_NON_FATAL

/*
 * policy actions
 */
typedef enum {
    TB_POLACT_CONTINUE,
    TB_POLACT_HALT,
} tb_policy_action_t;

/*
 * policy hash types
 */
typedef enum {
    TB_HTYPE_ANY,
    TB_HTYPE_HASHONLY,
} tb_hash_type_t;


/*
 * policies
 */

typedef struct __attribute__ ((__packed__)) {
    uuid_t       uuid;
    uint8_t      hash_alg;            /* TB_HALG_* */
    uint8_t      hash_type;           /* TB_HTYPE_* */
    uint32_t     reserved;
    uint8_t      num_hashes;
    tb_hash_t    hashes[];
} tb_policy_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t             version;      /* applies to this and tb_policy_t */
    uint8_t             policy_type;  /* TB_POLTYPE_* */
    uint32_t            reserved;
    uint8_t             num_policies;
    tb_policy_t         policies[];
} tb_policy_index_t;


/*
 * TPM NV indices
 */

#define TB_TCB_POLICY_IDX     0x20000001  /* policy index for TCB (VMM+dom0)*/


/*
 * policy UUIDs
 */

#define TBPOL_VMM_UUID      {0x756a5bfe, 0x5b0b, 0x4d33, 0xb867, \
                                         {0xd7, 0x83, 0xfb, 0x46, 0x36, 0xbf}}
#define TBPOL_DOM0_UUID     {0x894c909f, 0xd614, 0x4625, 0x8a2d, \
                                         {0x45, 0x3b, 0x80, 0x10, 0xca, 0x8c}}


#endif    /* __TB_POLICY_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

