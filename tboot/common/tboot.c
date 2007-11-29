/*
 * tboot.c: main entry point and "generic" routines for measured launch
 *          support
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
#include <types.h>
#include <stdbool.h>
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <printk.h>
#include <multiboot.h>
#include <processor.h>
#include <misc.h>
#include <page.h>
#include <msr.h>
#include <e820.h>
#include <uuid.h>
#include <elf.h>
#include <hash.h>
#include <txt/txt.h>
#include <tb_error.h>
#include <tb_policy.h>
#include <tboot.h>
#include <acpi.h>

extern void _prot_to_real(uint32_t dist_addr);
extern bool load_policy(void);
extern tb_error_t evaluate_all_policies(multiboot_info_t *mbi);
extern void apply_policy(tb_error_t error);

extern long s3_flag;

extern char _start[];            /* start of tboot */
extern char _end[];              /* end of tboot */
extern char s3_wakeup_16[];
extern char s3_wakeup_end[];

/* multiboot struct saved so that post_launch() can use it */
static multiboot_info_t *g_mbi;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/*
 * caution: must make sure the total wakeup entry code length
 * (s3_wakeup_end - s3_wakeup_16) can fit into one page.
 */
static uint8_t g_saved_s3_wakeup_page[PAGE_SIZE];


static bool verify_platform(void)
{
    return txt_verify_platform();
}

static bool is_launched(void)
{
    return txt_is_launched();
}

static bool prepare_cpu(void)
{
    return txt_prepare_cpu();
}

static bool prepare_platform(void)
{
    return txt_prepare_platform();
}

static bool launch_environment(multiboot_info_t *mbi)
{
    return txt_launch_environment(mbi);
}

static void copy_s3_wakeup_entry(void)
{
    if ( s3_wakeup_end - s3_wakeup_16 > PAGE_SIZE ) {
        printk("S3 entry is too large to be copied into one page!\n");
        return;
    }

    /* backup target address space first */
    memcpy(g_saved_s3_wakeup_page, (void *)TBOOT_S3_WAKEUP_ADDR,
           s3_wakeup_end - s3_wakeup_16);

    /* copy s3 entry into target mem */
    memcpy((void *)TBOOT_S3_WAKEUP_ADDR, s3_wakeup_16,
           s3_wakeup_end - s3_wakeup_16);
}

static void restore_saved_s3_wakeup_page(void)
{
    /* restore saved page */
    memcpy((void *)TBOOT_S3_WAKEUP_ADDR, g_saved_s3_wakeup_page,
           s3_wakeup_end - s3_wakeup_16);
}

static void post_launch(void)
{
    uint64_t base, size;
    tb_error_t err;
    bool is_measured_launch = false;
    extern tboot_log_t *g_log;
    extern void shutdown_entry32(void);
    extern void shutdown_entry64(void);

    /* TBD: need to handle errors here by tearing down */

    printk("measured launch succeeded\n");

    txt_post_launch();

    if ( s3_flag  ) {
        /* restore backuped s3 wakeup page */
        restore_saved_s3_wakeup_page();

        /* bring RLPs into environment */
        txt_wakeup_cpus();

        print_tboot_shared(&_tboot_shared);

        _prot_to_real(_tboot_shared.s3_k_wakeup_entry);
    }

    /* make copy of e820 map that we will adjust */
    if ( !copy_e820_map(g_mbi) )
        goto launch_xen;

    /* ensure the mbi is properly formatted, etc. */
    if ( !verify_modules(g_mbi) )
        goto launch_xen;

    /* marked mem regions used by TXT (heap, SINIT, etc.) as E820_UNUSABLE */
    if ( !txt_protect_mem_regions() )
        goto launch_xen;

    /* check tboot and the page table */
    base = (uint64_t)((unsigned long)&_start - 3*PAGE_SIZE);
    size = (uint64_t)((unsigned long)&_end - base);
    printk("verifying tboot and its page table (%Lx - %Lx) in e820 table\n\t",
           base, (base + size - 1));
    if ( e820_check_region(base, size) != E820_RAM ) {
        printk(": failed.\n");
        /* TBD: un-comment when new SINIT is released */
        /* goto launch_xen; */
    }
    else
        printk(": succeeded.\n");

    /* protect ourselves and the page table we created */
    base = (uint64_t)((unsigned long)&_start - 3*PAGE_SIZE);
    size = (uint64_t)(unsigned long)&_end - base;
    printk("protecting tboot (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, E820_UNUSABLE) )
        goto launch_xen;

    base = (uint32_t)&_tboot_shared;
    size = PAGE_SIZE;
    printk("protecting MLE/kernel shared (%Lx - %Lx) in e820 table\n",
           base, (base + size - 1));
    if ( !e820_protect_region(base, size, E820_UNUSABLE) )
        goto launch_xen;

    /* replace map in mbi with copy */
    replace_e820_map(g_mbi);

    printk("adjusted e820 map:\n");
    print_e820_map();

    /*
     * verify vmm and dom0 against tboot policy & TCB_manifest
     */
    err = evaluate_all_policies(g_mbi);
    apply_policy(err);

    /*
     * init MLE/kernel shared data page
     */
    memset(&_tboot_shared, 0, PAGE_SIZE);
    _tboot_shared.uuid = (uuid_t)TBOOT_SHARED_UUID;
    _tboot_shared.version = 0x02;
    _tboot_shared.log_addr = (uint32_t)g_log;
    _tboot_shared.shutdown_entry32 = (uint32_t)shutdown_entry32;
    _tboot_shared.shutdown_entry64 = (uint32_t)shutdown_entry64;
    _tboot_shared.s3_tb_wakeup_entry = (uint32_t)TBOOT_S3_WAKEUP_ADDR;
    _tboot_shared.tboot_base = (uint32_t)&_start;
    _tboot_shared.tboot_size = (uint32_t)&_end - (uint32_t)&_start;
    print_tboot_shared(&_tboot_shared);
    print_log();

    is_measured_launch = true;

    /* bring RLPs into environment */
    txt_wakeup_cpus();

launch_xen:
    launch_xen(g_mbi, is_measured_launch);
}

#define __STR(...)   #__VA_ARGS__
#define STR(...)      __STR(__VA_ARGS__)

void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec)
{
    printk("cpu %x waking up, SIPI vector=%x\n", cpuid, sipi_vec);

    /* change to real mode and then jump to SIPI vector */
    _prot_to_real(sipi_vec);
}

multiboot_info_t* begin_launch(multiboot_info_t *mbi)
{
    unsigned long apicbase;

    init_log();
    early_serial_init();

    printk("***************************************\n");
    printk("begin launch()\n");

    /* we should only be executing on the BSP */
    rdmsrl(MSR_IA32_APICBASE, apicbase);
    if ( !(apicbase & MSR_IA32_APICBASE_BSP) ) {
        printk("entry processor is not BSP\n");
        goto failed;
    }

    /* we need to make sure this is a (TXT-) capable platform before using */
    /* any of the features, incl. those required to check if the environment */
    /* has already been launched */

    /* make TPM ready for measured launch */
    if ( !prepare_platform() )
        goto failed;

    /* read tboot policy from TPM-NV (will use default if none in TPM-NV) */
    load_policy();

    /* need to verify that platform can perform measured launch */
    if ( !verify_platform() )
        goto failed;

    /* this is being called post-measured launch */
    if ( is_launched() ) {
        post_launch();
    }

    /* print any errors on last boot, which must be from TXT launch */
    txt_get_error();

    /* make the CPU ready for measured launch */
    if ( !prepare_cpu() )
        goto failed;

    /* do s3 launch directly, if is a s3 resume */
    if ( s3_flag ) {
        txt_s3_launch_environment();
        printk("we should never get here\n");
        return mbi;
    }
        
    /* check for error from previous boot */
    printk("checking previous errors on the last boot.\n\t");
    if ( was_last_boot_error() )
        printk("last boot has error.\n");
    else
        printk("last boot has no error.\n");

    /* save for post_launch */
    g_mbi = mbi;

    /* launch the measured environment */
    if ( !launch_environment(mbi) )
        goto failed;

    /* for Intel(r) TXT, we will never get here */
    printk("we should never get here\n");
    return mbi;

 failed:
    launch_xen(mbi, false);
    return mbi;
}

static void shutdown_system(uint32_t shutdown_type)
{
    long empty_idt[2] = {0, 0};

    printk("shutdown_system() called for shutdown_type=%x\n", shutdown_type);

    switch( shutdown_type ) {
        case TB_SHUTDOWN_REBOOT:
            /* just triple fault by loading 0-size IDT 
               then generating intrrupt */
            __asm__ __volatile__("lidt (%0)" : : "r" (&empty_idt));
            __asm__ __volatile__("int3");

        case TB_SHUTDOWN_S3:
            copy_s3_wakeup_entry();
        case TB_SHUTDOWN_S4:
        case TB_SHUTDOWN_S5:
            COMPILE_TIME_ASSERT(sizeof(_tboot_shared.acpi_sinfo)
                                 >= sizeof(acpi_sinfo_t));
            machine_sleep((acpi_sinfo_t *)_tboot_shared.acpi_sinfo);

        case TB_SHUTDOWN_HALT:
        default:
            for ( ; ; )
                __asm__ __volatile__ ( "hlt" );
    }
}

void shutdown(void)
{
    /* TBD:  cap dynamic PCRs (17, 18) */

    /* scrub any secrets by clearing their memory, then flush cache */
    /* we don't have any secrets to scrub, however */
    ;

    txt_shutdown();

    /* machine shutdown */
    shutdown_system(_tboot_shared.shutdown_type);
}

void handle_exception(void)
{
    printk("received exception; shutting down...\n");
    _tboot_shared.shutdown_type = TB_SHUTDOWN_REBOOT;
    shutdown();
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
