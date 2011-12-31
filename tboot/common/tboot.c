/*
 * tboot.c: main entry point and "generic" routines for measured launch
 *          support
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
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <printk.h>
#include <multiboot.h>
#include <processor.h>
#include <misc.h>
#include <page.h>
#include <msr.h>
#include <atomic.h>
#include <io.h>
#include <mutex.h>
#include <e820.h>
#include <uuid.h>
#include <loader.h>
#include <hash.h>
#include <mle.h>
#include <tb_error.h>
#include <txt/txt.h>
#include <txt/vmcs.h>
#include <txt/smx.h>
#include <txt/mtrrs.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#include <txt/verify.h>
#include <tb_policy.h>
#include <tboot.h>
#include <acpi.h>
#include <integrity.h>
#include <tpm.h>
#include <cmdline.h>

extern void _prot_to_real(uint32_t dist_addr);
extern bool set_policy(void);
extern void verify_all_modules(multiboot_info_t *mbi);
extern void apply_policy(tb_error_t error);
void s3_launch(void);

/* counter timeout for waiting for all APs to exit guests */
#define AP_GUEST_EXIT_TIMEOUT     0x01000000

extern long s3_flag;

extern char s3_wakeup_16[];
extern char s3_wakeup_end[];

extern atomic_t ap_wfs_count;

extern struct mutex ap_lock;

/* multiboot struct saved so that post_launch() can use it */
__data multiboot_info_t *g_mbi = NULL;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/*
 * caution: must make sure the total wakeup entry code length
 * (s3_wakeup_end - s3_wakeup_16) can fit into one page.
 */
static __data uint8_t g_saved_s3_wakeup_page[PAGE_SIZE];

unsigned long get_tboot_mem_end(void)
{
    return PAGE_UP((unsigned long)&_end);
}

static tb_error_t verify_platform(void)
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
    extern tboot_log_t *g_log;
    extern void shutdown_entry(void);

    printk("measured launch succeeded\n");

    txt_post_launch();

    /* backup DMAR table */
    save_vtd_dmar_table();

    if ( s3_flag  )
        s3_launch();

    /* remove all TXT modules before verifying modules */
    remove_txt_modules(g_mbi);

    /*
     * verify e820 table and adjust it to protect our memory regions
     */

    /* ensure all modules are in RAM */
    if ( !verify_modules(g_mbi) )
        apply_policy(TB_ERR_POST_LAUNCH_VERIFICATION);

    /* marked mem regions used by TXT (heap, SINIT, etc.) as E820_RESERVED */
    err = txt_protect_mem_regions();
    apply_policy(err);

    /* verify that tboot is in valid RAM (i.e. E820_RAM) */
    base = (uint64_t)TBOOT_BASE_ADDR;
    size = (uint64_t)((unsigned long)&_end - base);
    printk("verifying tboot and its page table (%Lx - %Lx) in e820 table\n\t",
           base, (base + size - 1));
    if ( e820_check_region(base, size) != E820_RAM ) {
        printk(": failed.\n");
        apply_policy(TB_ERR_FATAL);
    }
    else
        printk(": succeeded.\n");

    /* protect ourselves, MLE page table, and MLE/kernel shared page */
    base = (uint64_t)TBOOT_BASE_ADDR;
    size = (uint64_t)get_tboot_mem_end() - base;
    uint32_t mem_type = is_kernel_linux() ? E820_RESERVED : E820_UNUSABLE;
    printk("protecting tboot (%Lx - %Lx) in e820 table\n", base,
           (base + size - 1));
    if ( !e820_protect_region(base, size, mem_type) )
        apply_policy(TB_ERR_FATAL);

    /* if using memory logging, reserve log area */
    if ( g_log_targets & TBOOT_LOG_TARGET_MEMORY ) {
        base = TBOOT_SERIAL_LOG_ADDR;
        size = TBOOT_SERIAL_LOG_SIZE;
        printk("reserving tboot memory log (%Lx - %Lx) in e820 table\n", base,
               (base + size - 1));
        if ( !e820_protect_region(base, size, E820_RESERVED) )
            apply_policy(TB_ERR_FATAL);
    }

    /* replace map in mbi with copy */
    replace_e820_map(g_mbi);

    printk("adjusted e820 map:\n");
    print_e820_map();

    /*
     * verify modules against policy
     */
    verify_all_modules(g_mbi);

    /*
     * seal hashes of modules and VL policy to current value of PCR17 & 18
     */
    if ( !seal_pre_k_state() )
        apply_policy(TB_ERR_S3_INTEGRITY);

    /*
     * init MLE/kernel shared data page
     */
    memset(&_tboot_shared, 0, PAGE_SIZE);
    _tboot_shared.uuid = (uuid_t)TBOOT_SHARED_UUID;
    _tboot_shared.version = 6;
    _tboot_shared.log_addr = (uint32_t)g_log;
    _tboot_shared.shutdown_entry = (uint32_t)shutdown_entry;
    _tboot_shared.tboot_base = (uint32_t)&_start;
    _tboot_shared.tboot_size = (uint32_t)&_end - (uint32_t)&_start;
    uint32_t key_size = sizeof(_tboot_shared.s3_key);
    if ( tpm_get_random(2, _tboot_shared.s3_key, &key_size) != TPM_SUCCESS ||
         key_size != sizeof(_tboot_shared.s3_key) )
        apply_policy(TB_ERR_S3_INTEGRITY);
    _tboot_shared.num_in_wfs = atomic_read(&ap_wfs_count);
    if ( use_mwait() ) {
        _tboot_shared.flags |= TB_FLAG_AP_WAKE_SUPPORT;
        _tboot_shared.ap_wake_trigger = AP_WAKE_TRIGGER_DEF;
    }
    else if ( get_tboot_mwait() ) {
        printk("ap_wake_mwait specified but the CPU doesn't support it.\n");
    }

    print_tboot_shared(&_tboot_shared);

    launch_kernel(true);
    apply_policy(TB_ERR_FATAL);
}

void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec)
{
    printk("cpu %u waking up, SIPI vector=%x\n", cpuid, sipi_vec);

    /* change to real mode and then jump to SIPI vector */
    _prot_to_real(sipi_vec);
}

void begin_launch(multiboot_info_t *mbi)
{
    tb_error_t err;

    g_mbi = ( g_mbi == NULL ) ? mbi : g_mbi;  /* save for post launch */

    /* on pre-SENTER boot, copy command line to buffer in tboot image
       (so that it will be measured); buffer must be 0 -filled */
    if ( !is_launched() && !s3_flag ) {
        memset(g_cmdline, '\0', sizeof(g_cmdline));
        if ( g_mbi->flags & MBI_CMDLINE ) {
            /* don't include path in cmd line */
            const char *cmdline = skip_filename((char *)g_mbi->cmdline);
            if ( cmdline != NULL )
                strncpy(g_cmdline, cmdline, sizeof(g_cmdline)-1);
        }
    }

    /* always parse cmdline */
    tboot_parse_cmdline();

    /* initialize all logging targets */
    printk_init();

    printk("******************* TBOOT *******************\n");
    printk("   %s\n", TBOOT_CHANGESET);
    printk("*********************************************\n");

    printk("command line: %s\n", g_cmdline);
    if ( s3_flag )
        printk("resume from S3\n");

    /* clear resume vector on S3 resume so any resets will not use it */
    if ( !is_launched() && s3_flag )
        set_s3_resume_vector(&_tboot_shared.acpi_sinfo, 0);

    /* we should only be executing on the BSP */
    if ( !(rdmsr(MSR_APICBASE) & APICBASE_BSP) ) {
        printk("entry processor is not BSP\n");
        apply_policy(TB_ERR_FATAL);
    }
    printk("BSP is cpu %u\n", get_apicid());

    /* make copy of e820 map that we will use and adjust */
    if ( !s3_flag ) {
        if ( !copy_e820_map(g_mbi) )
            apply_policy(TB_ERR_FATAL);
    }

    /* we need to make sure this is a (TXT-) capable platform before using */
    /* any of the features, incl. those required to check if the environment */
    /* has already been launched */

    /* make TPM ready for measured launch */
    if ( !is_tpm_ready(0) )
        apply_policy(TB_ERR_TPM_NOT_READY);

    /* read tboot policy from TPM-NV (will use default if none in TPM-NV) */
    err = set_policy();
    apply_policy(err);

    /* need to verify that platform supports TXT before we can check error */
    /* (this includes TPM support) */
    err = supports_txt();
    apply_policy(err);

    /* print any errors on last boot, which must be from TXT launch */
    txt_get_error();

    /* need to verify that platform can perform measured launch */
    err = verify_platform();
    apply_policy(err);

    /* ensure there are modules */
    if ( !s3_flag && !verify_mbi(g_mbi) )
        apply_policy(TB_ERR_FATAL);

    /* this is being called post-measured launch */
    if ( is_launched() )
        post_launch();

    /* make the CPU ready for measured launch */
    if ( !prepare_cpu() )
        apply_policy(TB_ERR_FATAL);

    /* do s3 launch directly, if is a s3 resume */
    if ( s3_flag ) {
        txt_s3_launch_environment();
        printk("we should never get here\n");
        apply_policy(TB_ERR_FATAL);
    }

    /* check for error from previous boot */
    printk("checking previous errors on the last boot.\n\t");
    if ( was_last_boot_error() )
        printk("last boot has error.\n");
    else
        printk("last boot has no error.\n");

    if ( !prepare_tpm() )
        apply_policy(TB_ERR_TPM_NOT_READY);

    /* launch the measured environment */
    err = txt_launch_environment(mbi);
    apply_policy(err);
}

void s3_launch(void)
{
    /* restore backed-up s3 wakeup page */
    restore_saved_s3_wakeup_page();

    /* remove DMAR table if necessary */
    remove_vtd_dmar_table();

    if ( !is_launched() )
        apply_policy(TB_ERR_S3_INTEGRITY);
    else {
        /* this is being called post-measured launch */
        /* verify saved hash integrity and re-extend PCRs */
        if ( !verify_integrity() )
            apply_policy(TB_ERR_S3_INTEGRITY);
    }

    /* need to re-initialize this */
    _tboot_shared.num_in_wfs = atomic_read(&ap_wfs_count);

    print_tboot_shared(&_tboot_shared);

    /* (optionally) pause when transferring kernel resume */
    if ( g_vga_delay > 0 )
        delay(g_vga_delay * 1000);

    _prot_to_real(g_post_k_s3_state.kernel_s3_resume_vector);
}

static void shutdown_system(uint32_t shutdown_type)
{
    static const char *types[] = { "TB_SHUTDOWN_REBOOT", "TB_SHUTDOWN_S5",
                                   "TB_SHUTDOWN_S4", "TB_SHUTDOWN_S3",
                                   "TB_SHUTDOWN_HALT" };
    char type[32];

    if ( shutdown_type >= ARRAY_SIZE(types) )
        snprintf(type, sizeof(type), "unknown: %u", shutdown_type);
    else
        strncpy(type, types[shutdown_type], sizeof(type));
    printk("shutdown_system() called for shutdown_type: %s\n", type);

    switch( shutdown_type ) {
        case TB_SHUTDOWN_S3:
            copy_s3_wakeup_entry();
            /* write our S3 resume vector to ACPI resume addr */
            set_s3_resume_vector(&_tboot_shared.acpi_sinfo,
                                 TBOOT_S3_WAKEUP_ADDR);
            /* fall through for rest of Sx handling */
        case TB_SHUTDOWN_S4:
        case TB_SHUTDOWN_S5:
            machine_sleep(&_tboot_shared.acpi_sinfo);
            /* if machine_sleep() fails, fall through to reset */

        case TB_SHUTDOWN_REBOOT:
            if ( txt_is_powercycle_required() ) {
                /* powercycle by writing 0x0a+0x0e to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x0a);
                outb(0xcf9, 0x0e);
            }
            else {
                /* soft reset by writing 0xfe to keyboard reset vector 0x64 */
                /* BIOSes (that are not performing some special operation, */
                /* such as update) will turn this into a platform reset as */
                /* expected. */
                outb(0x64, 0xfe);
                /* fall back to soft reset by writing 0x06 to port 0xcf9 */
                /* (supported by all TXT-capable chipsets) */
                outb(0xcf9, 0x06);
            }

        case TB_SHUTDOWN_HALT:
        default:
            while ( true )
                halt();
    }
}

static void cap_pcrs(void)
{
    bool was_capped[TPM_NR_PCRS] = {false};
    tpm_pcr_value_t cap_val;   /* use whatever val is on stack */

    /* ensure PCRs 17 + 18 are always capped */
    tpm_pcr_extend(2, 17, &cap_val, NULL);
    tpm_pcr_extend(2, 18, &cap_val, NULL);
    was_capped[17] = was_capped[18] = true;

    /* also cap every dynamic PCR we extended (only once) */
    /* don't cap static PCRs since then they would be wrong after S3 resume */
    memset(&was_capped, true, TPM_PCR_RESETABLE_MIN*sizeof(bool));
    for ( int i = 0; i < g_pre_k_s3_state.num_vl_entries; i++ ) {
        if ( !was_capped[g_pre_k_s3_state.vl_entries[i].pcr] ) {
            tpm_pcr_extend(2, g_pre_k_s3_state.vl_entries[i].pcr, &cap_val,
                           NULL);
            was_capped[g_pre_k_s3_state.vl_entries[i].pcr] = true;
        }
    }

    printk("cap'ed dynamic PCRs\n");
}

void shutdown(void)
{
    static atomic_t ap_in_shutdown;

    /* wait-for-sipi only invoked for APs, so skip all BSP shutdown code */
    if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_WFS ) {
        atomic_inc(&ap_in_shutdown);
        _tboot_shared.ap_wake_trigger = 0;
        mtx_enter(&ap_lock);
        printk("shutdown(): TB_SHUTDOWN_WFS\n");
        if ( use_mwait() )
            ap_wait(get_apicid());
        else
            handle_init_sipi_sipi(get_apicid());
        apply_policy(TB_ERR_FATAL);
    }

    printk("wait until all APs ready for txt shutdown\n");
    while( atomic_read(&ap_wfs_count) < atomic_read(&ap_in_shutdown) )
        cpu_relax();

    /* ensure localities 0, 1 are inactive (in case kernel used them) */
    release_locality(0);
    release_locality(1);

    if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_S3 ) {
        /* restore DMAR table if needed */
        restore_vtd_dmar_table();

        /* save kernel/VMM resume vector for sealing */
        g_post_k_s3_state.kernel_s3_resume_vector =
            _tboot_shared.acpi_sinfo.kernel_s3_resume_vector;

        /* create and seal memory integrity measurement */
        if ( !seal_post_k_state() )
            apply_policy(TB_ERR_S3_INTEGRITY);
            /* OK to leave key in memory on failure since if user cared they
               would have policy that doesn't continue for TB_ERR_S3_INTEGRITY
               error */
        else
            /* wipe S3 key from memory now that it is sealed */
            memset(_tboot_shared.s3_key, 0, sizeof(_tboot_shared.s3_key));
    }

    /* cap dynamic PCRs extended as part of launch (17, 18, ...) */
    if ( is_launched() ) {

        /* cap PCRs to ensure no follow-on code can access sealed data */
        cap_pcrs();

        /* have TPM save static PCRs (in case VMM/kernel didn't) */
        /* per TCG spec, TPM can invalidate saved state if any other TPM
           operation is performed afterwards--so do this last */
        if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_S3 )
            tpm_save_state(2);

        /* scrub any secrets by clearing their memory, then flush cache */
        /* we don't have any secrets to scrub, however */
        ;

        /* in mwait "mode", APs will be in MONITOR/MWAIT and can be left there */
        if ( !use_mwait() ) {
            /* force APs to exit mini-guests if any are in and wait until */
            /* all are out before shutting down TXT */
            printk("waiting for APs (%u) to exit guests...\n",
                   atomic_read(&ap_wfs_count));
            force_aps_exit();
            uint32_t timeout = AP_GUEST_EXIT_TIMEOUT;
            do {
                if ( timeout % 0x8000 == 0 )
                    printk(".");
                else
                    cpu_relax();
                if ( timeout % 0x200000 == 0 )
                    printk("\n");
                timeout--;
            } while ( ( atomic_read(&ap_wfs_count) > 0 ) && timeout > 0 );
            printk("\n");
            if ( timeout == 0 )
                printk("AP guest exit loop timed-out\n");
            else
                printk("all APs exited guests\n");
        }

        /* turn off TXT (GETSEC[SEXIT]) */
        txt_shutdown();
    }

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
