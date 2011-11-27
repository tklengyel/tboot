/*
 * loader.c: support functions for manipulating ELF/Linux kernel
 *           binaries
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
#include <stdbool.h>
#include <types.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <page.h>
#include <multiboot.h>
#include <uuid.h>
#include <loader.h>
#include <e820.h>
#include <tboot.h>
#include <elf_defns.h>
#include <linux_defns.h>
#include <tb_error.h>
#include <txt/txt.h>

/* copy of kernel/VMM command line so that can append 'tboot=0x1234' */
static char *new_cmdline = (char *)TBOOT_KERNEL_CMDLINE_ADDR;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/* multiboot struct saved so that post_launch() can use it (in tboot.c) */
extern multiboot_info_t *g_mbi;

extern bool is_elf_image(const void *image, size_t size);
extern bool expand_elf_image(const elf_header_t *elf, void **entry_point);
extern bool expand_linux_image(const void *linux_image, size_t linux_size,
                               const void *initrd_image, size_t initrd_size,
                               void **entry_point, bool is_measured_launch);
extern bool jump_elf_image(const void *entry_point);
extern bool jump_linux_image(const void *entry_point);
extern bool is_sinit_acmod(const void *acmod_base, uint32_t acmod_size, bool quiet);

#if 0
void print_mbi(const multiboot_info_t *mbi)
{
    /* print mbi for debug */
    unsigned int i;

    printk("print mbi@%p ...\n", mbi);
    printk("\t flags: 0x%x\n", mbi->flags);
    if ( mbi->flags & MBI_MEMLIMITS )
        printk("\t mem_lower: %uKB, mem_upper: %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ( mbi->flags & MBI_BOOTDEV ) {
        printk("\t boot_device.bios_driver: 0x%x\n",
               mbi->boot_device.bios_driver);
        printk("\t boot_device.top_level_partition: 0x%x\n",
               mbi->boot_device.top_level_partition);
        printk("\t boot_device.sub_partition: 0x%x\n",
               mbi->boot_device.sub_partition);
        printk("\t boot_device.third_partition: 0x%x\n",
               mbi->boot_device.third_partition);
    }
    if ( mbi->flags & MBI_CMDLINE )
        printk("\t cmdline@0x%x: \"%s\"\n", mbi->cmdline, (char *)mbi->cmdline);
    if ( mbi->flags & MBI_MODULES ) {
        printk("\t mods_count: %u, mods_addr: 0x%x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
            printk("\t     %d : mod_start: 0x%x, mod_end: 0x%x\n", i,
                   p->mod_start, p->mod_end);
            printk("\t         string (@0x%x): \"%s\"\n", p->string,
                   (char *)p->string);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        printk("\t aout :: tabsize: 0x%x, strsize: 0x%x, addr: 0x%x\n",
               p->tabsize, p->strsize, p->addr);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        printk("\t elf :: num: %u, size: 0x%x, addr: 0x%x, shndx: 0x%x\n",
               p->num, p->size, p->addr, p->shndx);
    }
    if ( mbi->flags & MBI_MEMMAP ) {
        memory_map_t *p;
        printk("\t mmap_length: 0x%x, mmap_addr: 0x%x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
	        printk("\t     size: 0x%x, base_addr: 0x%04x%04x, "
                   "length: 0x%04x%04x, type: %u\n", p->size,
                   p->base_addr_high, p->base_addr_low,
                   p->length_high, p->length_low, p->type);
        }
    }
    if ( mbi->flags & MBI_DRIVES ) {
        printk("\t drives_length: %u, drives_addr: 0x%x\n", mbi->drives_length,
               mbi->drives_addr);
    }
    if ( mbi->flags & MBI_CONFIG ) {
        printk("\t config_table: 0x%x\n", mbi->config_table);
    }
    if ( mbi->flags & MBI_BTLDNAME ) {
        printk("\t boot_loader_name@0x%x: %s\n",
               mbi->boot_loader_name, (char *)mbi->boot_loader_name);
    }
    if ( mbi->flags & MBI_APM ) {
        printk("\t apm_table: 0x%x\n", mbi->apm_table);
    }
    if ( mbi->flags & MBI_VBE ) {
        printk("\t vbe_control_info: 0x%x\n"
               "\t vbe_mode_info: 0x%x\n"
               "\t vbe_mode: 0x%x\n"
               "\t vbe_interface_seg: 0x%x\n"
               "\t vbe_interface_off: 0x%x\n"
               "\t vbe_interface_len: 0x%x\n",
               mbi->vbe_control_info,
               mbi->vbe_mode_info,
               mbi->vbe_mode,
               mbi->vbe_interface_seg,
               mbi->vbe_interface_off,
               mbi->vbe_interface_len
              );
    }
}
#endif

bool verify_mbi(const multiboot_info_t *mbi)
{
    if ( mbi == NULL ) {
        printk("Error: Mbi pointer is zero.\n");
        return false;
    }

    if ( !(mbi->flags & MBI_MODULES) ) {
        printk("Error: Mods in mbi is invalid.\n");
        return false;
    }

    if ( mbi->mods_count < 1 ) {
        printk("Error: no modules\n");
        return false;
    }

    return true;
}

static void *remove_module(multiboot_info_t *mbi, void *mod_start)
{
    module_t *m = NULL;
    unsigned int i;

    if ( !verify_mbi(mbi) )
        return NULL;

    for ( i = 0; i < mbi->mods_count; i++ ) {
        m = get_module(mbi, i);
        if ( mod_start == NULL || (void *)m->mod_start == mod_start )
            break;
    }

    /* not found */
    if ( m == NULL ) {
        printk("could not find module to remove\n");
        return NULL;
    }

    /* if we're removing the first module (i.e. the "kernel") then need to */
    /* adjust some mbi fields as well */
    if ( mod_start == NULL ) {
        mbi->cmdline = m->string;
        mbi->flags |= MBI_CMDLINE;
        mod_start = (void *)m->mod_start;
    }

    /* copy remaing mods down by one */
    memmove(m, m + 1, (mbi->mods_count - i - 1)*sizeof(module_t));

    mbi->mods_count--;

    return mod_start;
}

static bool adjust_kernel_cmdline(multiboot_info_t *mbi,
                                  const void *tboot_shared_addr)
{
    const char *old_cmdline;

    /* assumes mbi is valid */

    if ( mbi->flags & MBI_CMDLINE && mbi->cmdline != 0 )
        old_cmdline = (const char *)mbi->cmdline;
    else
        old_cmdline = "";

    snprintf(new_cmdline, TBOOT_KERNEL_CMDLINE_SIZE, "%s tboot=%p",
             old_cmdline, tboot_shared_addr);
    new_cmdline[TBOOT_KERNEL_CMDLINE_SIZE - 1] = '\0';

    mbi->cmdline = (u32)new_cmdline;
    mbi->flags |= MBI_CMDLINE;

    return true;
}

bool is_kernel_linux(void)
{
    if ( !verify_mbi(g_mbi) )
        return false;

    module_t *m = (module_t *)g_mbi->mods_addr;
    void *kernel_image = (void *)m->mod_start;
    size_t kernel_size = m->mod_end - m->mod_start;

    return !is_elf_image(kernel_image, kernel_size);
}

/*
 * remove (all) SINIT and LCP policy data modules (if present)
 */
bool remove_txt_modules(multiboot_info_t *mbi)
{
    if ( mbi->mods_count == 0 || mbi->mods_addr == 0 ) {
        printk("Error: no module.\n");
        return false;
    }

    /* start at end of list so that we can remove w/in the loop */
    for ( unsigned int i = mbi->mods_count - 1; i > 0; i-- ) {
        module_t *m = get_module(mbi, i);
        void *base = (void *)m->mod_start;

        if ( is_sinit_acmod(base, m->mod_end - (unsigned long)base, true) ) {
            if ( remove_module(g_mbi, base) == NULL ) {
                printk("failed to remove SINIT module from module list\n");
                return false;
            }
        }
    }

    void *base = NULL;
    if ( find_lcp_module(g_mbi, &base, NULL) ) {
        if ( remove_module(g_mbi, base) == NULL ) {
            printk("failed to remove LCP module from module list\n");
            return false;
        }
    }

    return true;
}

extern unsigned long get_tboot_mem_end(void);

static bool below_tboot(unsigned long addr)
{
    return addr >= 0x100000 && addr < TBOOT_BASE_ADDR;
}

static unsigned long max(unsigned long a, unsigned long b)
{
    return (a > b) ? a : b;
}

unsigned long get_mbi_mem_end(const multiboot_info_t *mbi)
{
    unsigned long end = (unsigned long)(mbi + 1);

    if ( mbi->flags & MBI_CMDLINE )
        end = max(end, mbi->cmdline + strlen((char *)mbi->cmdline) + 1);
    if ( mbi->flags & MBI_MODULES ) {
        end = max(end, mbi->mods_addr + mbi->mods_count * sizeof(module_t));
        unsigned int i;
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = get_module(mbi, i);
            end = max(end, p->string + strlen((char *)p->string) + 1);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        end = max(end, p->addr + p->tabsize
                       + sizeof(unsigned long) + p->strsize);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        end = max(end, p->addr + p->num * p->size);
    }
    if ( mbi->flags & MBI_MEMMAP )
        end = max(end, mbi->mmap_addr + mbi->mmap_length);
    if ( mbi->flags & MBI_DRIVES )
        end = max(end, mbi->drives_addr + mbi->drives_length);
    /* mbi->config_table field should contain */
    /*  "the address of the rom configuration table returned by the */
    /*  GET CONFIGURATION bios call", so skip it */
    if ( mbi->flags & MBI_BTLDNAME )
        end = max(end, mbi->boot_loader_name
                       + strlen((char *)mbi->boot_loader_name) + 1);
    if ( mbi->flags & MBI_APM )
        /* per Grub-multiboot-Main Part2 Rev94-Structures, apm size is 20 */
        end = max(end, mbi->apm_table + 20);
    if ( mbi->flags & MBI_VBE ) {
        /* VBE2.0, VBE Function 00 return 512 bytes*/
        end = max(end, mbi->vbe_control_info + 512);
        /* VBE2.0, VBE Function 01 return 256 bytes*/
        end = max(end, mbi->vbe_mode_info + 256);
    }

    return PAGE_UP(end);
}

static void fixup_modules(const multiboot_info_t *mbi, size_t offset)
{
    for ( unsigned int i = 0; i < mbi->mods_count; i++ ) {
        module_t *m = get_module(mbi, i);
        if ( below_tboot(m->mod_start) ) {
            m->mod_start += offset;
            m->mod_end += offset;
        }
        if ( below_tboot(m->string) )
            m->string += offset;
    }
}

/*
 * fixup_mbi() fn is to be called after modules and/or mbi are moved from below
 * tboot memory to above tboot. It will fixup all pointers in mbi if mbi was
 * moved; fixup modules table if any modules are moved. If mbi was moved, return
 * the new mbi address otherwise return the old one.
 */
static multiboot_info_t *fixup_mbi(multiboot_info_t *mbi, size_t offset)
{
    bool moving_mbi = below_tboot((unsigned long)mbi);

    if ( moving_mbi ) {
        printk("mbi was moved from %p to ", mbi);
        mbi = (multiboot_info_t *)((unsigned long)mbi + offset);
        printk("%p\n", mbi);
    }

    if ( mbi->flags & MBI_MODULES ) {
        if ( below_tboot(mbi->mods_addr) )
            mbi->mods_addr += offset;
        fixup_modules(mbi, offset);
    }

    if ( !moving_mbi )
        return mbi;

    /* tboot replace mmap_addr w/ a copy, and make a copy of cmdline */
    /* because we modify it. Those pointers don't need offset adjustment. */
    /* To make it general and depend less on such kind of changes, just check */
    /* whether we need to adjust offset before trying to do it for each field */
    if ( (mbi->flags & MBI_CMDLINE) && below_tboot(mbi->cmdline) )
        mbi->cmdline += offset;

    if ( (mbi->flags & MBI_AOUT) && below_tboot(mbi->syms.aout_image.addr) )
        mbi->syms.aout_image.addr += offset;

    if ( (mbi->flags & MBI_ELF) && below_tboot(mbi->syms.elf_image.addr) )
        mbi->syms.elf_image.addr += offset;

    if ( (mbi->flags & MBI_MEMMAP) && below_tboot(mbi->mmap_addr) )
        mbi->mmap_addr += offset;

    if ( (mbi->flags & MBI_DRIVES) && below_tboot(mbi->drives_addr) )
        mbi->drives_addr += offset;

    if ( (mbi->flags & MBI_CONFIG) && below_tboot(mbi->config_table) )
        mbi->config_table += offset;

    if ( (mbi->flags & MBI_BTLDNAME) && below_tboot(mbi->boot_loader_name) )
        mbi->boot_loader_name += offset;

    if ( (mbi->flags & MBI_APM) && below_tboot(mbi->apm_table) )
        mbi->apm_table += offset;

    if ( mbi->flags & MBI_VBE ) {
        if ( below_tboot(mbi->vbe_control_info) )
            mbi->vbe_control_info += offset;
        if ( below_tboot(mbi->vbe_mode_info) )
            mbi->vbe_mode_info += offset;
    }

    return mbi;
}

static uint32_t get_lowest_mod_start(const multiboot_info_t *mbi)
{
    uint32_t lowest = 0xffffffff;

    for ( unsigned int i = 0; i < mbi->mods_count; i++ ) {
        module_t *m = get_module(mbi, i);
        if ( m->mod_start < lowest )
            lowest = m->mod_start;
    }

    return lowest;
}

static uint32_t get_highest_mod_end(const multiboot_info_t *mbi)
{
    uint32_t highest = 0;

    for ( unsigned int i = 0; i < mbi->mods_count; i++ ) {
        module_t *m = get_module(mbi, i);
        if ( m->mod_end > highest )
            highest = m->mod_end;
    }

    return highest;
}

/*
 * Move any mbi components/modules/mbi that are below tboot to just above tboot
 */
static void move_modules(multiboot_info_t **mbi)
{
    unsigned long lowest = get_lowest_mod_start(*mbi);
    unsigned long from = 0;

    if ( below_tboot(lowest) )
        from = lowest;
    else if ( below_tboot((unsigned long)*mbi) )
        from = (unsigned long)*mbi;
    else
        return;

    unsigned long highest = get_highest_mod_end(*mbi);
    unsigned long to = PAGE_UP(highest);

    if ( to < get_tboot_mem_end() )
        to = get_tboot_mem_end();

    /*
     * assuming that all of the members of mbi (e.g. cmdline, 
     * syms.aout_image.addr, etc.) are contiguous with the mbi structure
     */
    if ( to < get_mbi_mem_end(*mbi) )
        to = get_mbi_mem_end(*mbi);

    memcpy((void *)to, (void *)from, TBOOT_BASE_ADDR - from);

    printk("0x%lx bytes copied from 0x%lx to 0x%lx\n",
           TBOOT_BASE_ADDR - from, from, to);
    *mbi = fixup_mbi(*mbi, to - from);
}

bool launch_kernel(bool is_measured_launch)
{
    enum { ELF, LINUX } kernel_type;
    void *kernel_entry_point;

    if ( !verify_mbi(g_mbi) )
        return false;

    /* remove all SINIT and LCP modules since kernel may not handle */
    remove_txt_modules(g_mbi);

    module_t *m = (module_t *)g_mbi->mods_addr;

    void *kernel_image = (void *)m->mod_start;
    size_t kernel_size = m->mod_end - m->mod_start;

    if ( is_elf_image(kernel_image, kernel_size) ) {
        printk("kernel is ELF format\n");
        kernel_type = ELF;
        /* fix for GRUB2, which may load modules into memory before tboot */
        move_modules(&g_mbi);
    }
    else {
        printk("assuming kernel is Linux format\n");
        kernel_type = LINUX;
    }

    /* print_mbi(g_mbi); */

    kernel_image = remove_module(g_mbi, NULL);
    if ( kernel_image == NULL )
        return false;

    if ( kernel_type == ELF ) {
        if ( is_measured_launch )
            adjust_kernel_cmdline(g_mbi, &_tboot_shared);
        if ( !expand_elf_image((elf_header_t *)kernel_image,
                               &kernel_entry_point) )
            return false;
        printk("transfering control to kernel @%p...\n", kernel_entry_point);
        /* (optionally) pause when transferring to kernel */
        if ( g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
        return jump_elf_image(kernel_entry_point);
    }
    else if ( kernel_type == LINUX ) {
        m = (module_t *)g_mbi->mods_addr;
        void *initrd_image = (void *)m->mod_start;
        size_t initrd_size = m->mod_end - m->mod_start;

        expand_linux_image(kernel_image, kernel_size,
                           initrd_image, initrd_size,
                           &kernel_entry_point, is_measured_launch);
        printk("transfering control to kernel @%p...\n", kernel_entry_point);
        /* (optionally) pause when transferring to kernel */
        if ( g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
        return jump_linux_image(kernel_entry_point);
    }

    printk("unknown kernel type\n");
    return false;
}

module_t *get_module(const multiboot_info_t *mbi, unsigned int i)
{
    if ( mbi == NULL ) {
        printk("Error: mbi pointer is zero.\n");
        return NULL;
    }

    if ( i >= mbi->mods_count ) {
        printk("invalid module #\n");
        return NULL;
    }

    return (module_t *)(mbi->mods_addr + i * sizeof(module_t));
}

static bool find_module(const multiboot_info_t *mbi, void **base, size_t *size,
                        const void *data, size_t len)
{
    if ( mbi == NULL ) {
        printk("Error: mbi pointer is zero.\n");
        return false;
    }

    if ( base == NULL ) {
        printk("Error: base is NULL.\n");
        return false;
    }

    *base = NULL;
    if ( size != NULL )
        *size = 0;

    if ( mbi->mods_count == 0 || mbi->mods_addr == 0 ) {
        printk("Error: no module.\n");
        return false;
    }

    for ( unsigned int i = mbi->mods_count - 1; i > 0; i-- ) {
        module_t *m = get_module(mbi, i);
        /* check size */
        size_t mod_size = m->mod_end - m->mod_start;
        if ( len > mod_size ) {
            printk("Error: image size is smaller than data size.\n");
            return false;
        }
        if ( memcmp((void *)m->mod_start, data, len) == 0 ) {
            *base = (void *)m->mod_start;
            if ( size != NULL )
                *size = mod_size;
            return true;
        }
    }

    return false;
}

/*
 * find_module_by_uuid
 *
 * find a module by its uuid
 *
 */
bool find_module_by_uuid(const multiboot_info_t *mbi, void **base, size_t *size,
                         const uuid_t *uuid)
{
    return find_module(mbi, base, size, uuid, sizeof(*uuid));
}

/*
 * find_module_by_file_signature
 *
 * find a module by its file signature
 *
 */
bool find_module_by_file_signature(const multiboot_info_t *mbi, void **base,
                                   size_t *size, const char* file_signature)
{
    return find_module(mbi, base, size, file_signature, strlen(file_signature));
}

bool verify_modules(const multiboot_info_t *mbi)
{
    uint64_t base, size;
    module_t *m;

    /* assumes mbi is valid */

    /* verify e820 map to make sure each module is OK in e820 map */
    /* check modules in mbi should be in RAM */
    for ( unsigned int i = 0; i < mbi->mods_count; i++ ) {
        m = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
        base = m->mod_start;
        size = m->mod_end - m->mod_start;
        printk("verifying module %d of mbi (%Lx - %Lx) in e820 table\n\t",
               i, base, (base + size - 1));
        if ( e820_check_region(base, size) != E820_RAM ) {
            printk(": failed.\n");
            return false;
        }
        else
            printk(": succeeded.\n");
    }

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
