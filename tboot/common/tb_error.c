/*
 * tb_error.c: support functions for tb_error_t type
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
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <multiboot.h>
#include <uuid.h>
#include <hash.h>
#include <tb_error.h>
#include <tb_policy.h>
#include <tpm.h>
#include <tboot.h>
#include <txt/config_regs.h>

#define TB_LAUNCH_ERR_IDX     0x20000002      /* launch error index */

static bool no_err_idx;

/*
 * print_tb_error_msg
 *
 * print tb policy error message
 *
 */
void print_tb_error_msg(tb_error_t error)
{
    switch( error ) {
        case TB_ERR_NONE:
            printk("succeeded.\n");
            break;
        case TB_ERR_FIXED:
            printk("previous error has been fixed.\n");
            break;
        case TB_ERR_GENERIC:
            printk("non-fatal generic error.\n");
            break;
        case TB_ERR_TPM_NOT_READY:
            printk("TPM not ready.\n");
            break;
        case TB_ERR_SMX_NOT_SUPPORTED:
            printk("SMX not supported.\n");
            break;
        case TB_ERR_VMX_NOT_SUPPORTED:
            printk("VMX not supported.\n");
            break;
        case TB_ERR_TXT_NOT_SUPPORTED:
            printk("TXT not supported.\n");
            break;
        case TB_ERR_MODULES_NOT_IN_POLICY:
            printk("modules in mbi but not in policy.\n");
            break;
        case TB_ERR_MODULE_VERIFICATION_FAILED:
            printk("verifying module against policy failed.\n");
            break;
        case TB_ERR_POLICY_INVALID:
            printk("policy invalid.\n");
            break;
        case TB_ERR_POLICY_NOT_PRESENT:
            printk("no policy in TPM NV.\n");
            break;
        case TB_ERR_SINIT_NOT_PRESENT:
            printk("SINIT ACM not provided.\n");
            break;
        case TB_ERR_ACMOD_VERIFY_FAILED:
            printk("verifying AC module failed.\n");
            break;
        case TB_ERR_POST_LAUNCH_VERIFICATION:
            printk("verification of post-launch failed.\n");
            break;
        case TB_ERR_S3_INTEGRITY:
            printk("creation or verification of S3 measurements failed.\n");
            break;
        case TB_ERR_FATAL:
            printk("generic fatal error.\n");
            break;
        default:
            printk("unknown error (%d).\n", error);
            break;
    }
}

/*
 * read_tb_error_code
 *
 * read error code from TPM NV (TB_LAUNCH_ERR_IDX)
 *
 */
bool read_tb_error_code(tb_error_t *error)
{
    uint32_t size = sizeof(tb_error_t);
    uint32_t ret;

    if ( error == NULL ) {
        printk("Error: error pointer is zero.\n");
        return false;
    }

    memset(error, 0, size);

    /* read! */
    ret = tpm_nv_read_value(0, TB_LAUNCH_ERR_IDX, 0, (uint8_t *)error, &size);
    if ( ret != TPM_SUCCESS ) {
        printk("Error: read TPM error: 0x%x.\n", ret);
	no_err_idx = true;
        return false;
    }

    no_err_idx = false;
    return true;
}

/*
 * write_tb_error_code
 *
 * write error code into TPM NV (TB_LAUNCH_ERR_IDX)
 *
 */
bool write_tb_error_code(tb_error_t error)
{
    if ( no_err_idx )
        return false;

    uint32_t ret = tpm_nv_write_value(0, TB_LAUNCH_ERR_IDX, 0,
				      (uint8_t *)&error, sizeof(tb_error_t));
    if ( ret != TPM_SUCCESS ) {
        printk("Error: write TPM error: 0x%x.\n", ret);
	no_err_idx = true;
        return false;
    }

    return true;
}

/*
 * was_last_boot_error
 * false: no error; true: error
 */
bool was_last_boot_error(void)
{
    tb_error_t error;
    txt_errorcode_t txt_err;

    /* check TB_LAUNCH_ERR_IDX */
    if ( read_tb_error_code(&error) ) {
        if ( error != TB_ERR_FIXED )
            return true;
    }

    /* check TXT.ERRORCODE */
    txt_err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if ( txt_err.valid && txt_err.type > 0 )
        return true;

    return false;
}

