/*
 * errors.c: parse and return status of Intel(r) TXT error codes
 *
 * Copyright (c) 2003-2011, Intel Corporation
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
#include <stdbool.h>
#include <types.h>
#include <printk.h>
#include <tb_error.h>
#include <txt/txt.h>
#include <txt/config_regs.h>
#include <txt/errorcode.h>


static void display_errors(void)
{
    txt_errorcode_t err;
    txt_ests_t ests;
    txt_e2sts_t e2sts;
    txt_errorcode_sw_t sw_err;
    acmod_error_t acmod_err;

    /*
     * display TXT.ERRORODE error
     */
    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    printk("TXT.ERRORCODE: 0x%Lx\n", err._raw);

    /* AC module error (don't know how to parse other errors) */
    if ( err.valid ) {
        if ( err.external == 0 )       /* processor error */
            printk("\t processor error 0x%x\n", (uint32_t)err.type);
        else {                         /* external SW error */
            sw_err._raw = err.type;
            if ( sw_err.src == 1 )     /* unknown SW error */
                printk("unknown SW error 0x%x:0x%x\n", sw_err.err1, sw_err.err2);
            else {                     /* ACM error */
                acmod_err._raw = sw_err._raw;
                printk("AC module error : acm_type=0x%x, progress=0x%02x, "
                       "error=0x%x\n", acmod_err.acm_type, acmod_err.progress,
                       acmod_err.error);
                /* error = 0x0a, progress = 0x0d => TPM error */
                if ( acmod_err.error == 0x0a && acmod_err.progress == 0x0d )
                    printk("TPM error code = 0x%x\n", acmod_err.tpm_err);
                /* progress = 0x10 => LCP2 error */
                else if ( acmod_err.progress == 0x10 && acmod_err.lcp_minor != 0 )
                    printk("LCP2 error:  minor error = 0x%x, index = %u\n",
                           acmod_err.lcp_minor, acmod_err.lcp_index);
            }
        }
    }

    /*
     * display TXT.ESTS error
     */
    ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    printk("TXT.ESTS: 0x%Lx\n", ests._raw);

    /*
     * display TXT.E2STS error
     */
    e2sts = (txt_e2sts_t)read_pub_config_reg(TXTCR_E2STS);
    printk("TXT.E2STS: 0x%Lx\n", e2sts._raw);
}

bool txt_get_error(void)
{
    txt_errorcode_t err;

    display_errors();

    err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
    if ( err.valid )
        return false;
    else
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
