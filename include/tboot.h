/*
 * tboot.h: shared data structure with MLE and kernel and functions
 *          used by kernel for runtime support
 *
 * Copyright (c) 2006-2009, Intel Corporation
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

#ifndef __TBOOT_H__
#define __TBOOT_H__

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

/* define uuid_t here in case uuid.h wasn't pre-included */
/* (i.e. so tboot.h can be self-sufficient) */
#ifndef __UUID_H__
typedef struct __packed {
  uint32_t    data1;
  uint16_t    data2;
  uint16_t    data3;
  uint16_t    data4;
  uint8_t     data5[6];
} uuid_t;
#endif

/*
 * used to communicate between tboot and the launched kernel (i.e. Xen)
 */

/* GAS - Generic Address Structure (ACPI 2.0+) */
typedef struct __packed {
    uint8_t  space_id;
    uint8_t  bit_width;
    uint8_t  bit_offset;
    uint8_t  access_width;
    uint64_t address;
} tboot_acpi_generic_address_t;

typedef struct __packed {
    tboot_acpi_generic_address_t pm1a_cnt_blk;
    tboot_acpi_generic_address_t pm1b_cnt_blk;
    tboot_acpi_generic_address_t pm1a_evt_blk;
    tboot_acpi_generic_address_t pm1b_evt_blk;
    uint16_t pm1a_cnt_val;
    uint16_t pm1b_cnt_val;
    uint64_t wakeup_vector;
    uint32_t vector_width;
    uint64_t kernel_s3_resume_vector;
} tboot_acpi_sleep_info_t;

typedef struct __packed {
    /* version 3+ fields: */
    uuid_t    uuid;              /* {663C8DFF-E8B3-4b82-AABF-19EA4D057A08} */
    uint32_t  version;           /* currently 0.3 */
    uint32_t  log_addr;          /* physical addr of log or NULL if none */
    uint32_t  shutdown_entry;    /* entry point for tboot shutdown */
    uint32_t  shutdown_type;     /* type of shutdown (TB_SHUTDOWN_*) */
    tboot_acpi_sleep_info_t
              acpi_sinfo;        /* where kernel put acpi sleep info in Sx */
    uint32_t  tboot_base;        /* starting addr for tboot */
    uint32_t  tboot_size;        /* size of tboot */
} tboot_shared_t;

#define TB_SHUTDOWN_REBOOT      0
#define TB_SHUTDOWN_S5          1
#define TB_SHUTDOWN_S4          2
#define TB_SHUTDOWN_S3          3
#define TB_SHUTDOWN_HALT        4

/* {663C8DFF-E8B3-4b82-AABF-19EA4D057A08} */
#define TBOOT_SHARED_UUID    {0x663c8dff, 0xe8b3, 0x4b82, 0xaabf, \
                                 {0x19, 0xea, 0x4d, 0x5, 0x7a, 0x8 }}

/*
 * used to log tboot printk output
 */

typedef struct {
    uuid_t     uuid;
    uint32_t   max_size;
    uint32_t   curr_pos;
    char       *buf;
} tboot_log_t;

/* {C0192526-6B30-4db4-844C-A3E953B88174} */
#define TBOOT_LOG_UUID   {0xc0192526, 0x6b30, 0x4db4, 0x844c, \
                             {0xa3, 0xe9, 0x53, 0xb8, 0x81, 0x74 }}


extern tboot_shared_t *g_tboot_shared;

static inline bool tboot_in_measured_env(void)
{
    return (g_tboot_shared != NULL);
}

static inline void print_tboot_shared(tboot_shared_t *tboot_shared)
{
    printk("tboot_shared data:\n");
    printk("\t version: %d\n", tboot_shared->version);
    printk("\t log_addr: 0x%08x\n", tboot_shared->log_addr);
    printk("\t shutdown_entry: 0x%08x\n", tboot_shared->shutdown_entry);
    printk("\t shutdown_type: %d\n", tboot_shared->shutdown_type);
    printk("\t tboot_base: 0x%08x\n", tboot_shared->tboot_base);
    printk("\t tboot_size: 0x%x\n", tboot_shared->tboot_size);
}


#endif    /* __TBOOT_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
