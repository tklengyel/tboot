/*
 * txt-stat: Linux app that will display various information about
 *           the status of TXT.
 *
 * Copyright (c) 2006-2008, Intel Corporation
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

#include <features.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

/* tboot code assumes 4k pages */
#ifdef PAGE_SHIFT
#undef PAGE_SHIFT
#endif
#define PAGE_SHIFT       12
#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif
#define PAGE_SIZE        (1 << PAGE_SHIFT)

#define printk   printf
#include "../include/config.h"
#include "../include/uuid.h"
#include "../include/tboot.h"
#include "../tboot/include/txt/config_regs.h"

/*
 * BIOS structure
 */
typedef struct {
    uint32_t  version;              /* WB = 2, current = 3 */
    uint32_t  bios_sinit_size;
    uint64_t  lcp_pd_base;
    uint64_t  lcp_pd_size;
    uint32_t  num_logical_procs;
    uint64_t  flags;                /* v3+ */
} bios_data_t;
typedef void   txt_heap_t;
static inline bios_data_t *get_bios_data_start(txt_heap_t *heap)
{
    return (bios_data_t *)((char*)heap + sizeof(uint64_t));
}

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
    txt_dpr_t dpr;

    printf("Intel(r) TXT Configuration Registers:\n");

    /* STS */
    sts._raw = read_txt_config_reg(txt_config_base, TXTCR_STS);
    printf("\tSTS: 0x%08jx\n", sts._raw);
    printf("\t    senter_done: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t    sexit_done: %s\n", bit_to_str(sts.sexit_done_sts));
    printf("\t    mem_unlock: %s\n", bit_to_str(sts.mem_unlock_sts));
    printf("\t    mem_config_lock: %s\n", bit_to_str(sts.mem_config_lock_sts));
    printf("\t    private_open: %s\n", bit_to_str(sts.private_open_sts));
    printf("\t    mem_config_ok: %s\n", bit_to_str(sts.mem_config_ok_sts));

    /* ESTS */
    ests._raw = read_txt_config_reg(txt_config_base, TXTCR_ESTS);
    printf("\tESTS: 0x%02jx\n", ests._raw);
    printf("\t    txt_reset: %s\n", bit_to_str(ests.txt_reset_sts));
    printf("\t    txt_wake_error: %s\n", bit_to_str(ests.txt_wake_error_sts));

    /* E2STS */
    e2sts._raw = read_txt_config_reg(txt_config_base, TXTCR_E2STS);
    printf("\tE2STS: 0x%016jx\n", e2sts._raw);
    printf("\t    slp_entry_error: %s\n",
           bit_to_str(e2sts.slp_entry_error_sts));
    printf("\t    secrets: %s\n", bit_to_str(e2sts.secrets_sts));
    printf("\t    block_mem: %s\n", bit_to_str(e2sts.block_mem_sts));
    printf("\t    reset: %s\n", bit_to_str(e2sts.reset_sts));

    /* ERRORCODE */
    printf("\tERRORCODE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_ERRORCODE));

    /* DIDVID */
    txt_didvid_t didvid;
    didvid._raw = read_txt_config_reg(txt_config_base, TXTCR_DIDVID);
    printf("\tDIDVID: 0x%016jx\n", didvid._raw);
    printf("\t    vendor_id: 0x%x\n", didvid.vendor_id);
    printf("\t    device_id: 0x%x\n", didvid.device_id);
    printf("\t    revision_id: 0x%x\n", didvid.revision_id);

    /* SINIT.BASE/SIZE */
    printf("\tSINIT.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                        TXTCR_SINIT_BASE));
    printf("\tSINIT.SIZE: %juB (0x%jx)\n",
           read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE),
           read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE));

    /* HEAP.BASE/SIZE */
    printf("\tHEAP.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
                                                       TXTCR_HEAP_BASE));
    printf("\tHEAP.SIZE: %juB (0x%jx)\n",
           read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE),
           read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE));

    /* DPR.BASE/SIZE */
    dpr._raw = read_txt_config_reg(txt_config_base, TXTCR_DPR);
    printf("\tDPR: 0x%016jx\n", dpr._raw);
    printf("\t    lock: %s\n", bit_to_str(dpr.lock));
    printf("\t    top: 0x%08x\n", dpr.top << 20);
    printf("\t    size: %uMB (%uB)\n", dpr.size, dpr.size*1024*1024);

    /* easy-to-see status of TXT and secrets */
    printf("***********************************************************\n");
    printf("\t TXT measured launch: %s\n", bit_to_str(sts.senter_done_sts));
    printf("\t secrets flag set: %s\n", bit_to_str(e2sts.secrets_sts));
    printf("***********************************************************\n");
}

static void print_bios_data(bios_data_t *bios_data)
{
    printf("bios_data (@%p, %jx):\n", bios_data,
           *((uint64_t *)bios_data - 1));
    printf("\t version: %u\n", bios_data->version);
    printf("\t bios_sinit_size: 0x%x (%u)\n", bios_data->bios_sinit_size,
           bios_data->bios_sinit_size);
    printf("\t lcp_pd_base: 0x%jx\n", bios_data->lcp_pd_base);
    printf("\t lcp_pd_size: 0x%jx (%ju)\n", bios_data->lcp_pd_size,
           bios_data->lcp_pd_size);
    printf("\t num_logical_procs: %u\n", bios_data->num_logical_procs);
    if ( bios_data->version >= 3 )
        printf("\t flags: 0x%08jx\n", bios_data->flags);
}

static void display_heap(txt_heap_t *heap)
{
    bios_data_t *bios_data = get_bios_data_start(heap);
    print_bios_data(bios_data);
}

static void display_tboot_log(void *log_base)
{
    static char buf[512];

    tboot_log_t *log = (tboot_log_t *)log_base;

    if ( !are_uuids_equal(&(log->uuid), &((uuid_t)TBOOT_LOG_UUID)) ) {
        printf("unable to find TBOOT log\n");
        return;
    }

    printf("TBOOT log:\n");
    printf("\t max_size=%x\n", log->max_size);
    printf("\t curr_pos=%x\n", log->curr_pos);
    printf("\t buf:\n");
    /* log->buf is phys addr of buf, which will not match where mmap has */
    /* map'ed us, but since it is always jsut past end of struct, use that */
    char *log_buf = (char *)log + sizeof(*log);
    /* log is too big for single printk(), so break it up */
    for ( int curr_pos = 0; curr_pos < log->curr_pos;
          curr_pos += sizeof(buf)-1 ) {
        strncpy(buf, log_buf + curr_pos, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        printf("%s", buf);
    }
    printf("\n");
}

static bool is_txt_supported(void)
{
    return true;
}

int main(int argc, char *argv[])
{
    txt_heap_t *heap = NULL;
    uint64_t heap_size = 0;
    void *buf = NULL;
    off_t seek_ret = -1;
    int read_ret = 0;

    if ( !is_txt_supported() ) {
        printf("Intel(r) TXT is not supported\n");
        return 1;
    }

    int fd_mem = open("/dev/mem", O_RDONLY);
    if ( fd_mem == -1 ) {
        printf("ERROR: cannot open /dev/mem\n");
        return 1;
    }

    /*
     * display public config regs
     */
    seek_ret = lseek(fd_mem, TXT_PUB_CONFIG_REGS_BASE, SEEK_SET);
    if ( seek_ret == -1 )
        printf("ERROR: seeking public config registers failed by lseek()"
               "\nTry to map memory to read by mmap()......\n");
    else {
        buf = malloc(TXT_CONFIG_REGS_SIZE);
        if ( buf == NULL )
            printf("ERROR: out of memory"
                   "\nTry to map memory to read by mmap()......\n");
        else {
            read_ret = read(fd_mem, buf, TXT_CONFIG_REGS_SIZE);
            if ( read_ret != TXT_CONFIG_REGS_SIZE ) {
                printf("ERROR: reading public config registers failed by read()"
                        "\nTry to map memory to read by mmap()......\n");
                free(buf);
            }
            else {
                display_config_regs(buf);
                /* get this and save it before we unmap config regs */
                heap = (txt_heap_t *)(uintptr_t)read_txt_config_reg(
                                                buf, TXTCR_HEAP_BASE);
                heap_size = read_txt_config_reg(buf, TXTCR_HEAP_SIZE);
                free(buf);
            }
        }
    }

    /*
     * try mmap to display public config regs,
     * since public config regs should be displayed always.
     */
    if ( heap == NULL && heap_size == 0 ) {
        void *txt_pub = mmap(NULL, TXT_CONFIG_REGS_SIZE, PROT_READ,
                             MAP_PRIVATE, fd_mem, TXT_PUB_CONFIG_REGS_BASE);
        if ( txt_pub == MAP_FAILED )
            printf("ERROR: cannot map config regs by mmap()\n");
        else {
            display_config_regs(txt_pub);
            /* get this and save it before we unmap config regs */
            heap = (txt_heap_t *)(uintptr_t)read_txt_config_reg(
                                            txt_pub, TXTCR_HEAP_BASE);
            heap_size = read_txt_config_reg(txt_pub, TXTCR_HEAP_SIZE);
            munmap(txt_pub, TXT_CONFIG_REGS_SIZE);
        }
    }

    /*
     * display heap
     */
    if ( heap != NULL && heap_size != 0 ) {
        seek_ret = lseek(fd_mem, (off_t)heap, SEEK_SET);
        if ( seek_ret == -1 ) {
            printf("ERROR: seeking TXT heap failed by lseek()\n");
            goto try_display_log;
        }
        buf = malloc(heap_size);
        if ( buf == NULL ) {
            printf("ERROR: out of memory\n");
            goto try_display_log;
        }
        read_ret = read(fd_mem, buf, heap_size);
        if ( read_ret != heap_size ) {
            printf("ERROR: reading TXT heap failed by read()\n");
            free(buf);
            goto try_display_log;
        }
        display_heap((txt_heap_t *)buf);
        free(buf);
    }

try_display_log:
    /*
     * display serial log from tboot memory (if exists)
     */
    seek_ret = lseek(fd_mem, TBOOT_SERIAL_LOG_ADDR, SEEK_SET);
    if ( seek_ret == -1 ) {
        printf("ERROR: seeking TBOOT log failed by lseek()\n");
        close(fd_mem);
        return 1;
    }
    buf = malloc(TBOOT_SERIAL_LOG_SIZE);
    if ( buf == NULL ) {
        printf("ERROR: out of memory\n");
        close(fd_mem);
        return 1;
    }
    read_ret = read(fd_mem, buf, TBOOT_SERIAL_LOG_SIZE);
    if ( read_ret != TBOOT_SERIAL_LOG_SIZE ) {
        printf("ERROR: reading TBOOT log failed by read()\n");
        free(buf);
        close(fd_mem);
        return 1;
    }
    display_tboot_log(buf);
    free(buf);
    close(fd_mem);

    return 0;
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
