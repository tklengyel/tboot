/*
 * tpm.c: TPM-related support functions
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
#include <misc.h>
#include <compiler.h>
#include <processor.h>
#include <io.h>
#include <string.h>
#include <tpm.h>
#include <sha1.h>

__data struct tpm_if *g_tpm = NULL;
u16 tboot_alg_list[] = {TB_HALG_SHA1,
                        TB_HALG_SHA256};

/*
 * TPM registers and data structures
 *
 * register values are offsets from each locality base
 * see {read,write}_tpm_reg() for data struct format
 */

/* TPM_ACCESS_x */
#define TPM_REG_ACCESS           0x00
typedef union {
    u8 _raw[1];                      /* 1-byte reg */
    struct __packed {
        u8 tpm_establishment   : 1;  /* RO, 0=T/OS has been established
                                        before */
        u8 request_use         : 1;  /* RW, 1=locality is requesting TPM use */
        u8 pending_request     : 1;  /* RO, 1=other locality is requesting
                                        TPM usage */
        u8 seize               : 1;  /* WO, 1=seize locality */
        u8 been_seized         : 1;  /* RW, 1=locality seized while active */
        u8 active_locality     : 1;  /* RW, 1=locality is active */
        u8 reserved            : 1;
        u8 tpm_reg_valid_sts   : 1;  /* RO, 1=other bits are valid */
    };
} tpm_reg_access_t;

/* TPM_STS_x */
#define TPM_REG_STS              0x18
typedef union {
    u8 _raw[3];                  /* 3-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 self_test_done  : 1;  /* RO, only for version 2 */
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are
                                    valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
    };
} tpm12_reg_sts_t;

typedef union {
    u8 _raw[4];                  /* 4-byte reg */
    struct __packed {
        u8 reserved1       : 1;
        u8 response_retry  : 1;  /* WO, 1=re-send response */
        u8 self_test_done  : 1;  /* RO, only for version 2 */
        u8 expect          : 1;  /* RO, 1=more data for command expected */
        u8 data_avail      : 1;  /* RO, 0=no more data for response */
        u8 tpm_go          : 1;  /* WO, 1=execute sent command */
        u8 command_ready   : 1;  /* RW, 1=TPM ready to receive new cmd */
        u8 sts_valid       : 1;  /* RO, 1=data_avail and expect bits are
                                    valid */
        u16 burst_count    : 16; /* RO, # read/writes bytes before wait */
        /* version >= 2 */
        u8 command_cancel       : 1;
        u8 reset_establishment  : 1;
        u8 tpm_family           : 2;
        u8 reserved2            : 4;
    };
} tpm20_reg_sts_t;

/* Global variables for TPM status register */
static tpm20_reg_sts_t       g_reg_sts, *g_reg_sts_20 = &g_reg_sts;
static tpm12_reg_sts_t       *g_reg_sts_12 = (tpm12_reg_sts_t *)&g_reg_sts;

static u8 g_tpm_family = 0;

/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT * g_tpm->timeout.timeout_d)  /* let it long enough */
#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

#define read_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

#define write_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

static void tpm_send_cmd_ready_status(uint32_t locality)
{
    /* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
    memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.command_ready = 1;
    write_tpm_sts_reg(locality);
}

static bool tpm_check_cmd_ready_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO".");
#endif
    return g_reg_sts.command_ready;
}

static void tpm_print_status_register(void)
{
    if ( g_tpm_family == 0 )
    {
        printk(TBOOT_DETA"TPM: status reg content: %02x %02x %02x\n",
            (uint32_t)g_reg_sts_12->_raw[0],
            (uint32_t)g_reg_sts_12->_raw[1],
            (uint32_t)g_reg_sts_12->_raw[2]);
    }
    else
    {
        printk(TBOOT_DETA"TPM: status reg content: %02x %02x %02x %02x\n",
            (uint32_t)g_reg_sts_20->_raw[0],
            (uint32_t)g_reg_sts_20->_raw[1],
            (uint32_t)g_reg_sts_20->_raw[2],
            (uint32_t)g_reg_sts_20->_raw[3]);
    }
}

static u16 tpm_get_burst_count(uint32_t locality)
{
    read_tpm_sts_reg(locality);
    return g_reg_sts.burst_count;
}

static bool tpm_check_expect_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"Wait on Expect = 0, Status register %02x\n", g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.expect == 0;
}

static bool tpm_check_da_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"Waiting for DA Flag, Status register %02x\n", g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.data_avail == 1;
}

static void tpm_execute_cmd(uint32_t locality)
{
    memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.tpm_go = 1;
    write_tpm_sts_reg(locality);
}

bool tpm_validate_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_access_t reg_acc;

    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- ) {
        /*
         * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
         * other bits of access reg are valid.( but this bit will also be 1
         * while this locality is not available, so check seize bit too)
         * It also defines that reading reg_acc.seize should always return 0
         */
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.tpm_reg_valid_sts == 1 && reg_acc.seize == 0)
            return true;
        cpu_relax();
    }

    if ( i <= 0 )
        printk(TBOOT_ERR"TPM: tpm_validate_locality timeout\n");

    return false;
}

static bool tpm_wait_cmd_ready(uint32_t locality)
{
    uint32_t            i;
    tpm_reg_access_t    reg_acc;

#if 0 /* some tpms doesn't always return 1 for reg_acc.tpm_reg_valid_sts */
      /* and this bit was checked in tpm_validate_locality() already, */
      /* so safe to skip the check here */
    /* ensure the contents of the ACCESS register are valid */
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"TPM: Access reg content: 0x%02x\n", (uint32_t)reg_acc._raw[0]);
#endif
    if ( reg_acc.tpm_reg_valid_sts == 0 ) {
        printk(TBOOT_ERR"TPM: Access reg not valid\n");
        return false;
    }
#endif
    /* request access to the TPM from locality N */
    reg_acc._raw[0] = 0;
    reg_acc.request_use = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: access reg request use timeout\n");
        return false;
    }

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(TBOOT_INFO"TPM: wait for cmd ready ");
#endif
    i = 0;
    do {
        tpm_send_cmd_ready_status(locality);
        cpu_relax();
        /* then see if it has */

        if ( tpm_check_cmd_ready_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );
#ifdef TPM_TRACE
    printk(TBOOT_INFO"\n");
#endif

    if ( i > TPM_CMD_READY_TIME_OUT ) {
        tpm_print_status_register();
        printk(TBOOT_INFO"TPM: tpm timeout for command_ready\n");
        goto RelinquishControl;
    }

    return true;

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return false;
}

bool tpm_submit_cmd(u32 locality, u8 *in, u32 in_size,
                    u8 *out, u32 *out_size)
{
    u32 i, rsp_size, offset;
    u16 row_size;
    tpm_reg_access_t    reg_acc;
    bool ret = true;

    if ( locality >= TPM_NR_LOCALITIES ) {
        printk(TBOOT_WARN"TPM: Invalid locality for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in == NULL || out == NULL || out_size == NULL ) {
        printk(TBOOT_WARN"TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        printk(TBOOT_WARN"TPM: in/out buf size must be larger than 10 bytes\n");
        return false;
    }

    if ( !tpm_validate_locality(locality) ) {
        printk(TBOOT_WARN"TPM: Locality %d is not open\n", locality);
        return false;
    }

    if ( !tpm_wait_cmd_ready(locality) )
        return false;

#ifdef TPM_TRACE
    {
        printk(TBOOT_DETA"TPM: cmd size = %d\nTPM: cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif

    /* write the command to the TPM FIFO */
    offset = 0;
    do {
        i = 0;
        do {
            /* find out how many bytes the TPM can accept in a row */
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )
                break;
            else
                cpu_relax();
            i++;
        } while ( i <= TPM_CMD_WRITE_TIME_OUT );
        if ( i > TPM_CMD_WRITE_TIME_OUT ) {
            printk(TBOOT_ERR"TPM: write cmd timeout\n");
            ret = false;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < in_size; row_size--, offset++ )
            write_tpm_reg(locality, TPM_REG_DATA_FIFO,
                          (tpm_reg_data_fifo_t *)&in[offset]);
    } while ( offset < in_size );

    i = 0;
    do {
        if ( tpm_check_expect_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: wait for expect becoming 0 timeout\n");
        ret = false;
        goto RelinquishControl;
    }

    /* command has been written to the TPM, it is time to execute it. */
    tpm_execute_cmd(locality);

    /* check for data available */
    i = 0;
    do {
        if ( tpm_check_da_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: wait for data available timeout\n");
        ret = false;
        goto RelinquishControl;
    }

    rsp_size = 0;
    offset = 0;
    do {
        /* find out how many bytes the TPM returned in a row */
        i = 0;
        do {
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )
                break;
            else
                cpu_relax();
            i++;
        } while ( i <= TPM_RSP_READ_TIME_OUT );
        if ( i > TPM_RSP_READ_TIME_OUT ) {
            printk(TBOOT_ERR"TPM: read rsp timeout\n");
            ret = false;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < *out_size; row_size--, offset++ ) {
            if ( offset < *out_size )
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&out[offset]);
            else {
                /* discard the responded bytes exceeding out buf size */
                tpm_reg_data_fifo_t discard;
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,
                             (tpm_reg_data_fifo_t *)&discard);
            }

            /* get outgoing data size */
            if ( offset == RSP_RST_OFFSET - 1 ) {
                reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET],
                             sizeof(rsp_size));
            }
        }
    } while ( offset < RSP_RST_OFFSET ||
              (offset < rsp_size && offset < *out_size) );

    *out_size = (*out_size > rsp_size) ? rsp_size : *out_size;

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: response size = %d\n", *out_size);
        printk(TBOOT_DETA"TPM: response content: ");
        print_hex("TPM: \t", out, *out_size);
    }
#endif

    tpm_send_cmd_ready_status(locality);

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return ret;
}

bool release_locality(uint32_t locality)
{
    uint32_t i;
#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: releasing locality %u\n", locality);
#endif

    if ( !tpm_validate_locality(locality) )
        return true;

    tpm_reg_access_t reg_acc;
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
    if ( reg_acc.active_locality == 0 )
        return true;

    /* make inactive by writing a 1 */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 0 )
            return true;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    printk(TBOOT_INFO"TPM: access reg release locality timeout\n");
    return false;
}

bool prepare_tpm(void)
{
    /*
     * must ensure TPM_ACCESS_0.activeLocality bit is clear
     * (: locality is not active)
     */

    return release_locality(0);
}

bool tpm_detect(void)
{
    g_tpm = &tpm_12_if; /* Don't leave g_tpm as NULL*/
    if ( !tpm_validate_locality(0) ) {
        printk(TBOOT_ERR"TPM: Locality 0 is not open\n");
        return false;
    }

    /* determine TPM family from command check */
    if ( g_tpm->check() )
        g_tpm_family = 0;
    else
        g_tpm_family = 1;
    printk(TBOOT_INFO"TPM: TPM Family 0x%d\n", g_tpm_family);
    if (g_tpm_family == 1)
        g_tpm = &tpm_20_if;
    else
        g_tpm = &tpm_12_if;

    g_tpm->cur_loc = 0;
    g_tpm->timeout.timeout_a = TIMEOUT_A;
    g_tpm->timeout.timeout_b = TIMEOUT_B;
    g_tpm->timeout.timeout_c = TIMEOUT_C;
    g_tpm->timeout.timeout_d = TIMEOUT_D;

    return g_tpm->init(g_tpm);
}

void tpm_print(struct tpm_if *ti)
{
    if ( ti == NULL )
        return;

    printk(TBOOT_INFO"TPM attribute:\n");
    printk(TBOOT_INFO"\t extend policy %d\n", ti->extpol);
    printk(TBOOT_INFO"\t current alg id 0x%x\n", ti->cur_alg);
    printk(TBOOT_INFO"\t timeout values: A: %u, B: %u, C: %u, D: %u\n",
            ti->timeout.timeout_a, ti->timeout.timeout_b, ti->timeout.timeout_c,
            ti->timeout.timeout_d);
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
