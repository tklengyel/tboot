/*
 * linux.c: support functions for manipulating Linux kernel binaries
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string2.h>
#include <multiboot.h>
#include <page.h>
#include <e820.h>
#include <tboot.h>
#include <linux_defns.h>
#include <cmdline.h>

#define SECTOR_SIZE (1 << 9)      /* 0x200 */

typedef struct __attribute__ ((__packed__)) {
    uint16_t length;
    uint32_t table;
} gdt_t;

#define __BOOT_CS    0x10
#define __BOOT_DS    0x18

extern multiboot_info_t *g_mbi;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

boot_params_t boot_params;

/* expand linux kernel with kernel image and initrd image */
bool expand_linux_image(const void *linux_image, size_t linux_size,
                        const void *initrd_image, size_t initrd_size,
                        void **entry_point)
{
    linux_kernel_header_t *hd;
    uint32_t real_mode_base, protected_mode_base;
    unsigned long real_mode_size, protected_mode_size;
        /* Note: real_mode_size + protected_mode_size = linux_size */
    uint32_t initrd_base;
    const char *kernel_cmdline;
    screen_info_t *screen = (screen_info_t *)&boot_params;
    int vid_mode = 0;
    int initrd_max_mem = 0;

    /* Check param */

    if ( linux_image == NULL ) {
        printk("Error: Linux kernel image is zero.\n");
        return false;
    }

    if ( linux_size == 0 ) {
        printk("Error: Linux kernel size is zero.\n");
        return false;
    }

    if ( linux_size < sizeof(linux_kernel_header_t) ) {
        printk("Error: Linux kernel size is too small.\n");
        return false;
    }

    hd = (linux_kernel_header_t *)(linux_image + KERNEL_HEADER_OFFSET);

    if ( hd == NULL ) {
        printk("Error: Linux kernel header is zero.\n");
        return false;
    }

    if ( entry_point == NULL ) {
        printk("Error: Output pointer is zero.\n");
        return false;
    }

    /* recommended layout
        0x0000 - 0x7FFF     Real mode kernel
        0x8000 - 0x8FFF     Stack and heap
        0x9000 - 0x90FF     Kernel command line
        for details, see linux_defns.h
    */

    /* if setup_sects is zero, set to default value 4 */
    if ( hd->setup_sects == 0 )
        hd->setup_sects = DEFAULT_SECTOR_NUM;
    if ( hd->setup_sects > MAX_SECTOR_NUM ) {
        printk("Error: Linux setup sectors %d exceed maximum limitation 64.\n",
                hd->setup_sects);
        return false;
    }

    /* set vid_mode */
    linux_parse_cmdline((char *)g_mbi->cmdline);
    if ( get_linux_vga(&vid_mode) )
        hd->vid_mode = vid_mode;

    /* compare to the magic number */
    if ( hd->header == HDRS_MAGIC ) {
        if ( hd->version < 0x0205 ) {
            printk("Error: Old kernel (<2.6.20) is not supported by tboot.\n");
            return false;
        }

        /* boot loader is grub, set type_of_loader to 0x7 */
        hd->type_of_loader = LOADER_TYPE_GRUB;

        /* set loadflags and heap_end_ptr */
        hd->loadflags |= FLAG_CAN_USE_HEAP;         /* can use heap */
        hd->heap_end_ptr = KERNEL_CMDLINE_OFFSET - BOOT_SECTOR_OFFSET;

        /* load initrd and set ramdisk_image and ramdisk_size */
        /* The initrd should typically be located as high in memory as
           possible, as it may otherwise get overwritten by the early
           kernel initialization sequence. */
        if ( get_linux_mem(&initrd_max_mem) )
            initrd_base = initrd_max_mem - initrd_size;
        else if ( (g_mbi->flags) & (1<<0) )
            initrd_base = (g_mbi->mem_upper << 10) + 0x100000 - initrd_size;
        else {
            printk("Error: Cannot determine where to load initrd for Linux.\n");
            return false;
        }
        initrd_base = initrd_base & PAGE_MASK;  /* page align */

        /* Check max and gear */
        /* should not exceed initrd_addr_max */
        if ( initrd_base + initrd_size > hd->initrd_addr_max ) {
            initrd_base = hd->initrd_addr_max - initrd_size;
            initrd_base = initrd_base & PAGE_MASK;
        }

        memmove((void *)initrd_base, initrd_image, initrd_size);
        printk("Initrd from 0x%lx to 0x%lx\n",
               (unsigned long)initrd_base,
               (unsigned long)(initrd_base + initrd_size));

        hd->ramdisk_image = initrd_base;
        hd->ramdisk_size = initrd_size;

        /* set cmd_line_ptr */
        real_mode_base = LEGACY_REAL_START;
        if ( (g_mbi->flags) & (1<<0) )
            real_mode_base = (g_mbi->mem_lower << 10) - REAL_MODE_SIZE;
        if ( real_mode_base < TBOOT_KERNEL_CMDLINE_ADDR +
             TBOOT_KERNEL_CMDLINE_SIZE )
            real_mode_base = TBOOT_KERNEL_CMDLINE_ADDR +
                TBOOT_KERNEL_CMDLINE_SIZE;
        if ( real_mode_base > LEGACY_REAL_START )
            real_mode_base = LEGACY_REAL_START;
        hd->cmd_line_ptr = real_mode_base + KERNEL_CMDLINE_OFFSET;
    }
    else {
        /* old kernel */
        printk("Error: Old kernel (< 2.6.20) is not supported by tboot.\n");
        return false;
    }

    real_mode_size = (hd->setup_sects + 1) * SECTOR_SIZE;
    protected_mode_size = linux_size - real_mode_size;

    if ( hd->loadflags & FLAG_LOAD_HIGH ) {
        protected_mode_base = BZIMAGE_PROTECTED_START;
                /* bzImage:0x100000 */
        /* Check: protected mode part cannot exceed mem_upper */
        if ( (g_mbi->flags) & (1<<0) )
            if ( (protected_mode_base + protected_mode_size)
                    > ((g_mbi->mem_upper << 10) + 0x100000) ) {
                printk("Error: Linux protected mode part (0x%lx ~ 0x%lx) "
                       "exceeds mem_upper (0x%lx ~ 0x%lx).\n",
                       (unsigned long)protected_mode_base,
                       (unsigned long)(protected_mode_base + protected_mode_size),
                       (unsigned long)0x100000,
                       (unsigned long)((g_mbi->mem_upper << 10) + 0x100000));
                return false;
            }
    }

    /* set address of tboot shared page */
    hd->tboot_shared_addr = (uint32_t)&_tboot_shared;

    /* load protected-mode part */
    memmove((void *)protected_mode_base, linux_image + real_mode_size,
            protected_mode_size);
    printk("Kernel (protected mode) from 0x%lx to 0x%lx\n",
           (unsigned long)protected_mode_base,
           (unsigned long)(protected_mode_base + protected_mode_size));

    /* load real-mode part */
    memmove((void *)real_mode_base, linux_image, real_mode_size);
    printk("Kernel (real mode) from 0x%lx to 0x%lx\n",
           (unsigned long)real_mode_base,
           (unsigned long)(real_mode_base + real_mode_size));

    /* copy cmdline */
    kernel_cmdline = skip_filename((const char *)g_mbi->cmdline);
    memcpy((void *)(real_mode_base + KERNEL_CMDLINE_OFFSET),
           (void *)(kernel_cmdline), strlen(kernel_cmdline));

    memset(&boot_params, 0, sizeof(boot_params));
    memcpy(&boot_params.hdr, hd, sizeof(*hd));

    /* detect e820 table */
    if (( g_mbi->flags ) & ( 1<<6 )) {
        memory_map_t *p;
        uint64_t addr, size;
        uint32_t type;
        int i;

        for ( i = 0, p = (memory_map_t *)g_mbi->mmap_addr;
              (uint32_t)p < g_mbi->mmap_addr + g_mbi->mmap_length;
              i++,
              p = (memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
            addr = ((uint64_t)p->base_addr_high << 32)
                | (uint64_t)p->base_addr_low;
            size = ((uint64_t)p->length_high << 32)
                | (uint64_t)p->length_low;
            type = p->type;
            boot_params.e820_map[i].addr = addr;
            boot_params.e820_map[i].size = size;
            boot_params.e820_map[i].type = type;
        }
        boot_params.e820_entries = i;
    }

    screen->orig_video_mode = 3;       /* BIOS 80*25 text mode */
    screen->orig_video_lines = 25;
    screen->orig_video_cols = 80;
    screen->orig_video_points = 16;    /* set font height to 16 pixels */
    screen->orig_video_isVGA = 1;      /* use VGA text screen setups */
    screen->orig_y = 24;               /* start display text in the last line
                                       of screen */

    *entry_point = (void *)hd->code32_start;
    return true;
}

/* jump to protected-mode code of kernel */
bool jump_linux_image(void *entry_point)
{
    static const uint64_t gdt_table[] __attribute__ ((aligned(16))) = {
        0, 0, 0x00c09b000000ffff, 0x00c093000000ffff};
    /* both 4G flat, CS: execute/read, DS: read/write */

    static gdt_t gdt;

    gdt.length = sizeof(gdt_table) - 1;
    gdt.table = (uint32_t)&gdt_table;

    /* load gdt with CS = 0x10 and DS = 0x18 */
    __asm__ __volatile__ (
     " lgdtl %0;            "
     " mov %1, %%ecx;       "
     " mov %%ecx, %%ds;     "
     " mov %%ecx, %%es;     "
     " mov %%ecx, %%fs;     "
     " mov %%ecx, %%gs;     "
     " mov %%ecx, %%ss;     "
     " ljmp %2, $(1f);      "
     " 1: xor %%ebp, %%ebp; "
     " xor %%edi, %%edi;    "
     " xor %%ebx, %%ebx;    "
     :: "m"(gdt), "i"(__BOOT_DS), "i"(__BOOT_CS));

    /* jump to protected-mode code */
    __asm__ __volatile__ (
     " mov %0, %%esi; "    /* esi holds address of boot_params */
     " jmp *%%edx;    "
     " ud2;           "
     :: "a"(&boot_params), "d"(entry_point));

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
