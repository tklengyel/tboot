/*
 * txt-stat: Linux app that will display various information about
 *           the status of TXT.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/page.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "../tboot/include/txt/config_regs.h"

#define TXT_CONFIG_REGS_SIZE        (NR_TXT_CONFIG_PAGES*PAGE_SIZE)

static inline uint64_t read_txt_config_reg(void *config_regs_base,
                                           uint32_t reg)
{
    /* these are MMIO so make sure compiler doesn't optimize */
    return *(volatile uint64_t *)(config_regs_base + reg);
}

static inline const char * bit_to_str(uint64_t b)
{
    return b ? "TRUE" : "FALSE";
}

static void display_config_regs(void *txt_config_base)
{
    txt_sts_t sts;
    txt_ests_t ests;
    txt_e2sts_t e2sts;
    printf("Intel(r) TXT Configuration Registers:\n");

    /* STS */
    sts._raw = read_txt_config_reg(txt_config_base, TXTCR_STS);
    printf("\tSTS: 0x%lx\n", sts._raw);
    printf("\t    senter_done: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t    sexit_done: %s\n", bit_to_str(sts.sexit_done_sts));
    printf("\t    mem_unlock: %s\n", bit_to_str(sts.mem_unlock_sts));
    printf("\t    mem_config_lock: %s\n", bit_to_str(sts.mem_config_lock_sts));
    printf("\t    private_open: %s\n", bit_to_str(sts.private_open_sts));
    printf("\t    mem_config_ok: %s\n", bit_to_str(sts.mem_config_ok_sts));

    /* ESTS */
    ests._raw = read_txt_config_reg(txt_config_base, TXTCR_ESTS);
    printf("\tESTS: 0x%lx\n", ests._raw);
    printf("\t    txt_rogue: %s\n", bit_to_str(ests.txt_rogue_sts));
    printf("\t    bm_write_attack: %s\n", bit_to_str(ests.bm_write_attack));
    printf("\t    bm_read_attack: %s\n", bit_to_str(ests.bm_read_attack));
    printf("\t    fsb_write_attack: %s\n", bit_to_str(ests.fsb_write_attack));
    printf("\t    fsb_read_attack: %s\n", bit_to_str(ests.fsb_read_attack));
    printf("\t    txt_wake_error: %s\n", bit_to_str(ests.txt_wake_error_sts));

    /* E2STS */
    e2sts._raw = read_txt_config_reg(txt_config_base, TXTCR_E2STS);
    printf("\tE2STS: 0x%lx\n", e2sts._raw);
    printf("\t    slp_entry_error: %s\n",
           bit_to_str(e2sts.slp_entry_error_sts));
    printf("\t    secrets: %s\n", bit_to_str(e2sts.secrets_sts));
    printf("\t    block_mem: %s\n", bit_to_str(e2sts.block_mem_sts));
    printf("\t    reset: %s\n", bit_to_str(e2sts.reset_sts));

    /* ERRORCODE */
    printf("\tERRORCODE: 0x%lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_ERRORCODE));

    /* DIDVID */
    txt_didvid_t didvid;
    didvid._raw = read_txt_config_reg(txt_config_base, TXTCR_DIDVID);
    printf("\tDIDVID: 0x%lx\n", didvid._raw);
    printf("\t    vendor_id: 0x%x\n", didvid.vendor_id);
    printf("\t    device_id: 0x%x\n", didvid.device_id);
    printf("\t    revision_id: 0x%x\n", didvid.revision_id);

    /* SINIT.BASE/SIZE */
    printf("\tSINIT.BASE: 0x%lx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_BASE));
    printf("\tSINIT.SIZE: 0x%lx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_SIZE));

    /* HEAP.BASE/SIZE */
    printf("\tHEAP.BASE: 0x%lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_BASE));
    printf("\tHEAP.SIZE: 0x%lx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_SIZE));

    /* easy-to-see status of TXT and secrets */
    printf("***********************************************************\n");
    printf("\t TXT measured launch: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t secrets flag set: %s\n", bit_to_str(e2sts.secrets_sts));
    printf("***********************************************************\n");
}

static bool is_txt_supported(void)
{
    return true;
}

int main(int argc, char *argv[])
{
    int fd_mem = -1;
    void *txt_pub = MAP_FAILED;
    int ret = 1;

    if ( !is_txt_supported() ) {
        printf("Intel(r) TXT is not supported\n");
        return 1;
    }

    fd_mem = open("/dev/mem", O_RDONLY);
    if ( fd_mem == -1 ) {
        printf("ERROR: cannot open /dev/mem\n");
        ret = 1;
        goto done;
    }

    txt_pub = mmap(NULL, TXT_CONFIG_REGS_SIZE, PROT_READ, MAP_PRIVATE, fd_mem,
                   TXT_PUB_CONFIG_REGS_BASE);
    if ( txt_pub == MAP_FAILED ) {
        printf("ERROR: cannot map /dev/mem\n");
        ret = 1;
        goto done;
    }

    /*
     * display config regs
     */
    display_config_regs(txt_pub);

    ret = 0;

 done:
    if ( txt_pub != MAP_FAILED )
        munmap(txt_pub, TXT_CONFIG_REGS_SIZE);
    if ( fd_mem != -1 )
        close(fd_mem);

    return ret;
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