/*
 * elf.c: support functions for manipulating ELF binaries
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
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string2.h>
#include <misc.h>
#include <page.h>
#include <multiboot.h>
#include <uuid.h>
#include <elf.h>
#include <e820.h>
#include <tboot.h>

/* copy of kernel/VMM command line so that can append 'tboot=0x1234' */
static char *new_cmdline = (char *)TBOOT_KERNEL_CMDLINE_ADDR;

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

/* multiboot struct saved so that post_launch() can use it (in tboot.c) */
extern multiboot_info_t *g_mbi;

#if 0
static void print_mbi(multiboot_info_t *mbi)
{
    /* print mbi for debug */
    int i;
    printk("print mbi ...\n");
    printk("flags = %x\n", mbi->flags);
    if ((mbi->flags) & ( 1<<0 ))
        printk("mem_lower = %uKB, mem_upper = %uKB\n", mbi->mem_lower,
               mbi->mem_upper);
    if ((mbi->flags) & ( 1<<1 ))
        printk("boot_device = %x\n", mbi->boot_device);
    if ((mbi->flags) & ( 1<<2 ))
        printk("cmdline = %s\n", (char *)mbi->cmdline);
    if ((mbi->flags) & ( 1<<3 )) {
        printk("mods_count = %x, mods_addr = %x\n", mbi->mods_count,
               mbi->mods_addr);
        for ( i = 0; i < mbi->mods_count; i++ ) {
	        module_t *p = (module_t *)(mbi->mods_addr + i*sizeof(module_t));
	        printk("\t %d : mod_start = 0x%x, mod_end = 0x%x\n"
                   "\t      string (@0x%x) = %s\n", i, p->mod_start,
                   p->mod_end, p->string, (char *)p->string);
        }
    }
    if ((mbi->flags) & ( 1<<4 )) {
        aout_symbol_table_t *p = &(mbi->u.aout_sym);
        printk("tabsize = %x, strsize = %x, addr = %x\n", p->tabsize,
               p->strsize, p->addr);
    }
    if ((mbi->flags) & ( 1<<5 )) {
        elf_section_header_table_t *p = &(mbi->u.elf_sec);
        printk("num = %x, size = %x, addr = %x, shndx = %x\n", p->num,
               p->size, p->addr, p->shndx);
    }
    if ((mbi->flags) & ( 1<<6 )) {
        memory_map_t *p;
        printk("mmap_length = %x, mmap_addr = %x\n", mbi->mmap_length,
               mbi->mmap_addr);
        for ( p = (memory_map_t *)mbi->mmap_addr;
              (uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
              p=(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size)) ) {
	        printk("size = %x, base_addr = 0x%x%x, length = 0x%x%x, "
                   "type = %x\n", p->size, p->base_addr_high,
                   p->base_addr_low, p->length_high, p->length_low, p->type);
        }
    }
}
#endif

static bool is_mods_valid(multiboot_info_t *mbi)
{
    if ( mbi == NULL ) {
        printk("Error: Mbi pointer is zero.\n");
        return false;
    }

    if ( !((mbi->flags) & (1<<3)) ) {
        printk("Error: Mods in mbi is invalid.\n");
        return false;
    }

    return true;
}

static bool is_elf_image(const void *image, const size_t size)
{
    elf_header_t *elf;

    if ( image == NULL ) {
        printk("Error: Pointer is zero.\n");
        return false;
    }

    /* check size */
    if ( sizeof(elf_header_t) > size ) {
        printk("Error: Image size is smaller than ELF header size.\n");
        return false;
    }

    elf = (elf_header_t *)image;

    /* check magic number for ELF */
    if ( (elf->e_ident[EI_MAG0] != ELFMAG0) ||
         (elf->e_ident[EI_MAG1] != ELFMAG1) ||
         (elf->e_ident[EI_MAG2] != ELFMAG2) ||
         (elf->e_ident[EI_MAG3] != ELFMAG3) ) {
        printk("Error: ELF magic number is not matched.\n");
        return false;
    }

    /* check data encoding in ELF */
    if ( elf->e_ident[EI_DATA] != ELFDATA2LSB ) {
        printk("Error: ELF data encoding is not the least significant "
               "byte occupying the lowest address.\n");
        return false;
    }

    /* check ELF image is executable? */
    if ( elf->e_type != ET_EXEC ) {
        printk("Error: ELF image is not executable.\n");
        return false;
    }

    /* check ELF image is for IA? */
    if ( elf->e_machine != EM_386 ) {
        printk("Error: ELF image is not for IA.\n");
        return false;
    }

    /* check ELF version is valid? */
    if ( elf->e_version != EV_CURRENT ) {
        printk("Error: ELF version is invalid.\n");
        return false;
    }

    if ( sizeof(elf_program_header_t) > elf->e_phentsize ) {
        printk("Error: Program size is smaller than program "
               "header size.\n");
        return false;
    }

    return true;
}

static bool expand_elf_image(const elf_header_t *elf, void **entry_point)
{
    if ( elf == NULL ) {
        printk("Error: ELF header pointer is zero.\n");
        return false;
    }

    if ( entry_point == NULL ) {
        printk("Error: Output pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    /* load elf image into memory */
    for ( int i = 0; i < elf->e_phnum; i++ ) {
        elf_program_header_t *ph = (elf_program_header_t *)
                         ((void *)elf + elf->e_phoff + i*elf->e_phentsize);

        if ( ph->p_type == PT_LOAD ) {
            memcpy((void *)ph->p_paddr, (void *)elf + ph->p_offset,
                   ph->p_filesz);
            memset((void *)(ph->p_paddr + ph->p_filesz), 0,
                   ph->p_memsz - ph->p_filesz);
        }
    }

    *entry_point = (void *)elf->e_entry;
    return true;
}

static bool adjust_xen_cmdline(multiboot_info_t *mbi,
                               const void *tboot_shared_addr)
{
    char *old_cmdline;

    /* assumes mbi is valid */

    if ( mbi->flags & MBI_CMDLINE && mbi->cmdline != 0 )
        old_cmdline = (char *)mbi->cmdline;
    else
        old_cmdline = "";

    snprintf(new_cmdline, TBOOT_KERNEL_CMDLINE_SIZE, "%s tboot=0x%p",
             old_cmdline, tboot_shared_addr);
    new_cmdline[TBOOT_KERNEL_CMDLINE_SIZE - 1] = '\0';

    mbi->cmdline = (u32)new_cmdline;
    mbi->flags |= MBI_CMDLINE;

    return true;
}

bool launch_xen(bool is_measured_launch)
{
    module_t *m;
    void *xen_base, *xen_entry_point;
    elf_header_t *xen_as_elf;
    size_t xen_size;

    if ( !is_mods_valid(g_mbi) )
        return false;

    m = (module_t *)g_mbi->mods_addr;

    xen_base = (void *)m->mod_start;
    xen_size = m->mod_end - m->mod_start;

    if ( !is_elf_image(xen_base, xen_size) )
        return false;

    xen_base = remove_module(g_mbi, NULL);
    if ( xen_base == NULL )
        return false;

    xen_as_elf = (elf_header_t *)xen_base;

    if ( !expand_elf_image(xen_as_elf, &xen_entry_point) )
        return false;

    if ( is_measured_launch )
        adjust_xen_cmdline(g_mbi, &_tboot_shared);

    printk("transfering control to xen @0x%p...\n", xen_entry_point);

    /* jump to xen start entry */
    __asm__ __volatile__ (
      "    jmp *%%ecx;    "
      "    ud2;           "
      :: "a" (MB_MAGIC), "b" (g_mbi), "c" (xen_entry_point));

    return true;
}

module_t *get_module(multiboot_info_t *mbi, int i)
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

/*
 * find_module_by_uuid
 *
 * find a module by its uuid
 *
 */
bool find_module_by_uuid(multiboot_info_t *mbi, void **base, size_t *size,
                         const uuid_t *uuid)
{
    module_t *m;
    size_t mod_size;
    int i;

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

    for ( i = mbi->mods_count - 1; i > 0; i-- ) {
        m = get_module(mbi, i);
        /* check size */
        mod_size = m->mod_end - m->mod_start;
        if ( sizeof(uuid_t) > mod_size ) {
            printk("Error: image size is smaller than UUID size.\n");
            return false;
        }
        if ( are_uuids_equal((void *)m->mod_start, uuid) ) {
            *base = (void *)m->mod_start;
            if ( size != NULL )
                *size = mod_size;
            return true;
        }
    }

    return false;
}

bool verify_modules(multiboot_info_t *mbi)
{
    uint64_t base, size;
    module_t *m;

    if ( !is_mods_valid(mbi) )
        return false;

    /* verify e820 map to make sure each module is OK in e820 map */
    /* check modules in mbi should be in RAM */
    for ( int i = 0; i < mbi->mods_count; i++ ) {
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

void *remove_module(multiboot_info_t *mbi, void *mod_start)
{
    module_t *m = NULL;
    int i;

    if (!is_mods_valid(mbi))
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


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
