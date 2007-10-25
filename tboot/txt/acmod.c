/*
 * acmod.c: support functions for use of Intel(r) TXT Authenticated
 *          Code (AC) Modules
 *
 * Copyright (c) 2003-2007, Intel Corporation
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
#include <string.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <txt/acmod.h>
#include <txt/heap.h>
#include <txt/config_regs.h>
#include <txt/smx.h>
#include <txt/mtrrs.h>

typedef struct {
    union {
        struct {
            uint8_t   chipset_acm_type;
            uint8_t   version;
            uint16_t  length;
            uint32_t  chipset_id_list;
        } v1;
        struct {
            uuid_t    uuid;
            uint8_t   chipset_acm_type;
            uint8_t   version;
            uint16_t  length;
            uint32_t  chipset_id_list;
            uint32_t  os_sinit_data_ver;
            uint32_t  mle_hdr_ver;
        } v2;
    };
} acm_info_table_t;

/* ACM UUID value */
const uuid_t ACM_UUID = {0x8024d6cd, 0x4733, 0x2a62, 0xf1d1,
                         {0x3a, 0x89, 0x3b, 0x11, 0x82, 0xbc}};

/* chipset_acm_type field values */
#define ACM_CHIPSET_TYPE_SINIT        0x01

typedef struct {
    uint32_t  flags;
    uint16_t  vendor_id;
    uint16_t  device_id;
    uint16_t  revision_id;
    uint16_t  reserved;
    uint32_t  extended_id;
} acm_chipset_id_t;

typedef struct {
    uint32_t           count;
    acm_chipset_id_t   chipset_ids[];
} acm_chipset_id_list_t;


#define ACM_MEM_TYPE_UC                 0x0100
#define ACM_MEM_TYPE_WC                 0x0200
#define ACM_MEM_TYPE_WT                 0x1000
#define ACM_MEM_TYPE_WP                 0x2000
#define ACM_MEM_TYPE_WB                 0x4000

/* this is arbitrary and can be increased when needed */
#define MAX_SUPPORTED_ACM_VERSIONS      16

typedef struct {
    struct {
        uint32_t mask;
        uint32_t version;
    } acm_versions[MAX_SUPPORTED_ACM_VERSIONS];
    int n_versions;
    uint32_t acm_max_size;
    uint32_t acm_mem_types;
    uint32_t senter_controls;
} getsec_parameters_t;

#define DEF_ACM_MAX_SIZE                0x8000
#define DEF_ACM_VER_MASK                0xffffffff
#define DEF_ACM_VER_SUPPORTED           0x00
#define DEF_ACM_MEM_TYPES               ACM_MEM_TYPE_UC
#define DEF_SENTER_CTRLS                0x00

static bool get_parameters(getsec_parameters_t *params)
{
    unsigned long cr4;
    uint32_t index, eax, ebx, ecx;
    int param_type;

    /* sanity check because GETSEC[PARAMETERS] will fail if not set */
    cr4 = read_cr4();
    if ( !(cr4 & X86_CR4_SMXE) ) {
        printk("SMXE not enabled, can't read parameters\n");
        return false;
    }

    memset(params, 0, sizeof(*params));
    params->acm_max_size = DEF_ACM_MAX_SIZE;
    params->acm_mem_types = DEF_ACM_MEM_TYPES;
    params->senter_controls = DEF_SENTER_CTRLS;
    index = 0;
    do {
        __getsec_parameters(index++, &param_type, &eax, &ebx, &ecx);
        /* the code generated for a 'switch' statement doesn't work in this */
        /* environment, so use if/else blocks instead */
        if ( param_type == 0 )
            ;
        else if ( param_type == 1 ) {
            if ( params->n_versions == MAX_SUPPORTED_ACM_VERSIONS )
                printk("number of supported ACM version exceeds "
                       "MAX_SUPPORTED_ACM_VERSIONS\n");
            else {
                params->acm_versions[params->n_versions].mask = ebx;
                params->acm_versions[params->n_versions].version = ecx;
                params->n_versions++;
            }
        }
        else if ( param_type == 2 )
            params->acm_max_size = eax & 0xffffffe0;
        else if ( param_type == 3 )
            params->acm_mem_types = eax & 0xffffffe0;
        else if ( param_type == 4 )
            params->senter_controls = (eax & 0x00007fff) >> 8;
        else {
            printk("unknown GETSEC[PARAMETERS] type: %d\n", param_type);
            param_type = 0;    /* set so that we break out of the loop */
        }
    } while ( param_type != 0 );

    if ( params->n_versions == 0 ) {
        params->acm_versions[0].mask = DEF_ACM_VER_MASK;
        params->acm_versions[0].version = DEF_ACM_VER_SUPPORTED;
        params->n_versions = 1;
    }

    return true;
}

static acm_info_table_t *get_acmod_info_table(acm_hdr_t* hdr)
{
    uint32_t user_area_off;

    /* this fn assumes that the ACM has already passed at least the initial */
    /* is_acmod() checks */

    user_area_off = (hdr->header_len + hdr->scratch_size) * 4;
    /* check that table is within module */
    if ( user_area_off + sizeof(acm_info_table_t) > hdr->size*4 ) {
        printk("ACM info table size too large: %x\n",
               user_area_off + sizeof(acm_info_table_t));
        return NULL;
    }

    return (acm_info_table_t *)((uint32_t)hdr + user_area_off);
}

static void print_acm_hdr(acm_hdr_t *hdr, const char *mod_name)
{
    acm_info_table_t *info_table;

    printk("AC module header dump for %s:\n",
           (mod_name == NULL) ? "?" : mod_name);
    printk("\t type=%x\n", hdr->module_type);
    printk("\t length=%x\n", hdr->header_len);
    printk("\t version=%x\n", hdr->header_ver);
    printk("\t id=%x\n", hdr->module_id);
    printk("\t vendor=%x\n", hdr->module_vendor);
    printk("\t date=%08x\n", hdr->date);
    printk("\t size*4=%x\n", hdr->size*4);
    printk("\t entry point=%08x:%08x\n", hdr->seg_sel,
           hdr->entry_point);
    printk("\t scratch_size=%x\n", hdr->scratch_size);

    printk("\t info_table:\n");
    info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL ) {
        printk("\t\t <invalid>\n");
        return;
    }
    if ( are_uuids_equal(&(info_table->v2.uuid), &ACM_UUID) ) {
        printk("\t\t uuid="); print_uuid(&info_table->v2.uuid);
        printk("\n");
        printk("\t\t chipset_acm_type=%x\n",
               (uint32_t)info_table->v2.chipset_acm_type);
        printk("\t\t version=%x\n", (uint32_t)info_table->v2.version);
        printk("\t\t length=%x\n", (uint32_t)info_table->v2.length);
        printk("\t\t chipset_id_list=%x\n",
               (uint32_t)info_table->v2.chipset_id_list);
        printk("\t\t os_sinit_data_ver=%x\n",
               (uint32_t)info_table->v2.os_sinit_data_ver);
        printk("\t\t mle_hdr_ver=%x\n", (uint32_t)info_table->v2.mle_hdr_ver);
    }
    else {
        printk("\t\tchipset_acm_type=%x\n",
               (uint32_t)info_table->v1.chipset_acm_type);
        printk("\t\tversion=%x\n", (uint32_t)info_table->v1.version);
        printk("\t\tlength=%x\n", (uint32_t)info_table->v1.length);
        printk("\t\tchipset_id_list=%x\n",
               (uint32_t)info_table->v1.chipset_id_list);
    }
}

uint32_t get_supported_os_sinit_data_ver(acm_hdr_t* hdr)
{
    acm_info_table_t *info_table;

    /* assumes that it passed is_sinit_acmod() */

    info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL )
        return 0x00;

    if ( are_uuids_equal(&(info_table->v2.uuid), &ACM_UUID) )
        return info_table->v2.os_sinit_data_ver;
    else
        return 0x01;
}

static bool is_acmod(void *acmod_base, uint32_t acmod_size, uint8_t *type)
{
    acm_hdr_t *acm_hdr;
    acm_info_table_t *info_table;

    acm_hdr = (acm_hdr_t *)acmod_base;

    /* first check size */
    if ( acmod_size < sizeof(acm_hdr_t) ) {
        printk("ACM size is too small: acmod_size=%x,"
               " sizeof(acm_hdr)=%x\n", acmod_size, sizeof(acm_hdr) );
        return false;
    }
    if ( acmod_size != acm_hdr->size * 4 ) {
        printk("ACM size is too small: acmod_size=%x,"
               " acm_hdr->size*4=%x\n", acmod_size, acm_hdr->size*4);
        return false;
    }

    /* then check type and vendor */
    if ( (acm_hdr->module_type != ACM_TYPE_CHIPSET) ||
         (acm_hdr->module_vendor != ACM_VENDOR_INTEL) ) {
        printk("ACM type/vendor mismatch: module_type=%x,"
               " module_vendor=%x\n", acm_hdr->module_type,
               acm_hdr->module_vendor);
        return false;
    }

    info_table = get_acmod_info_table(acm_hdr);
    if ( info_table == NULL )
        return false;

    /* check if ACM UUID is present */
    if ( are_uuids_equal(&(info_table->v2.uuid), &ACM_UUID) ) {
        if ( type != NULL )
            *type = info_table->v2.chipset_acm_type;
        /* there is forward compatibility, so this is just a warning */
        if ( info_table->v2.version != 0x02 )
            printk("ACM info_table version mismatch (%x)\n",
                   (unsigned int)info_table->v2.version);
    }
    else {
        if ( type != NULL )
            *type = info_table->v1.chipset_acm_type;
        /* there is forward compatibility, so this is just a warning */
        if ( info_table->v1.version != 0x01 )
            printk("ACM info_table version mismatch (%x)\n",
                   (unsigned int)info_table->v1.version);
    }

    return true;
}

bool is_sinit_acmod(void *acmod_base, uint32_t acmod_size)
{
    uint8_t type;

    if ( !is_acmod(acmod_base, acmod_size, &type) )
        return false;

    if ( type != ACM_CHIPSET_TYPE_SINIT ) {
        printk("ACM is not an SINIT ACM (%x)\n", type);
        return false;
    }

    return true;
}

bool does_acmod_match_chipset(acm_hdr_t* hdr)
{
    acm_info_table_t *info_table;
    acm_chipset_id_list_t *chipset_id_list;
    acm_chipset_id_t *chipset_id;
    txt_didvid_t didvid;
    uint32_t size, id_list_off;

    /* this fn assumes that the ACM has already passed the is_acmod() checks */

    info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL )
        return false;
    if ( are_uuids_equal(&(info_table->v2.uuid), &ACM_UUID) )
        id_list_off = info_table->v2.chipset_id_list;
    else
        id_list_off = info_table->v1.chipset_id_list;

    size = hdr->size * 4;

    /* check that chipset id table is w/in ACM */
    if ( id_list_off + sizeof(acm_chipset_id_t) > size ) {
        printk("ACM chipset id list is too big: chipset_id_list=%x\n",
               id_list_off);
        return false;
    }

    chipset_id_list = (acm_chipset_id_list_t *)((uint32_t)hdr + id_list_off);

    /* check that all entries are w/in ACM */
    if ( id_list_off + sizeof(acm_chipset_id_t) + 
         chipset_id_list->count * sizeof(acm_chipset_id_t) > size ) {
        printk("ACM chipset id entries are too big:"
               " chipset_id_list->count=%x\n", chipset_id_list->count);
        return false;
    }

    /* get chipset device and vendor id info */
    didvid._raw = read_pub_config_reg(TXTCR_DIDVID);
    printk("chipset ids: vendor=%x, device=%x, revision=%x\n",
           didvid.vendor_id, didvid.device_id, didvid.revision_id);

    printk("%x ACM chipset id entries:\n", chipset_id_list->count);
    for ( int i = 0; i < chipset_id_list->count; i++ ) {
        chipset_id = &(chipset_id_list->chipset_ids[i]);
        printk("\tvendor=%x, device=%x, flags=%x, revision=%x, "
               "extended=%x\n", (uint32_t)chipset_id->vendor_id,
               (uint32_t)chipset_id->device_id, chipset_id->flags,
               (uint32_t)chipset_id->revision_id, chipset_id->extended_id);

        if ( (didvid.vendor_id == chipset_id->vendor_id ) &&
             (didvid.device_id == chipset_id->device_id ) &&
             ( ( ( (chipset_id->flags & 0x1) == 0) && 
                 (didvid.revision_id == chipset_id->revision_id) ) ||
               ( ( (chipset_id->flags & 0x1) == 1) &&
                 ((didvid.revision_id & chipset_id->revision_id) != 0 ) ) ) )
            return true;
    }

    printk("ACM does not match chipset\n");

#ifdef CHIPSET_REVID_BUG
    return true;
#else
    return false;
#endif
}

acm_hdr_t *copy_sinit(acm_hdr_t *sinit)
{
    void *sinit_region_base;
    uint32_t sinit_region_size;
    txt_heap_t *txt_heap;
    bios_os_data_t *bios_os_data;

    /* get BIOS-reserved region from LT.SINIT.BASE config reg */
    sinit_region_base = (void*)(uint32_t)read_pub_config_reg(TXTCR_SINIT_BASE);
    sinit_region_size = (uint32_t)read_pub_config_reg(TXTCR_SINIT_SIZE);

    /*
     * check if BIOS already loaded an SINIT module there
     */
    txt_heap = get_txt_heap();
    bios_os_data = get_bios_os_data_start(txt_heap);
    /* BIOS has loaded an SINIT module, so verify that it is valid */
    if ( bios_os_data->bios_sinit_size != 0 ) {
        printk("BIOS has already loaded an SINIT module\n");
        /* is it a valid SINIT module? */
        if ( is_sinit_acmod(sinit_region_base,
                            bios_os_data->bios_sinit_size) ) {
            /* no other SINIT was provided so must use one BIOS provided */
            if ( sinit == NULL )
                return (acm_hdr_t *)sinit_region_base;

            /* is it newer than the one we've been provided? */
            if ( ((acm_hdr_t *)sinit_region_base)->date >= sinit->date ) {
                printk("BIOS-provided SINIT is newer, so using it\n");
                return (acm_hdr_t *)sinit_region_base;    /* yes */
            }
            else
                printk("BIOS-provided SINIT is older: date=%x\n",
                       ((acm_hdr_t *)sinit_region_base)->date);
        }
    }
    /* our SINIT is newer than BIOS's (or BIOS did not have one) */

    /* BIOS SINIT not present or not valid and none provided */
    if ( sinit == NULL )
        return NULL;

    /* make sure our SINIT fits in the reserved region */
    if ( (sinit->size * 4) > sinit_region_size ) {
        printk("BIOS-reserved SINIT size (%x) is too small for loaded "
               "SINIT (%x)\n", sinit_region_size, sinit->size*4);
        return NULL;
    }

    /* copy it there */
    memcpy(sinit_region_base, sinit, sinit->size*4);

    printk("copied SINIT (size=%x) to %p\n", sinit->size*4,
           sinit_region_base);

    return (acm_hdr_t *)sinit_region_base;
}


/*
 * Do some AC module sanity checks because any violations will cause
 * an TXT.RESET.  Instead detect these, print a desriptive message,
 * and skip SENTER/ENTERACCS
 */
bool verify_acmod(acm_hdr_t *acm_hdr)
{
    getsec_parameters_t params;
    uint32_t size;

    /* assumes this already passed is_acmod() test */

    size = acm_hdr->size * 4;        /* hdr size is in dwords, we want bytes */

    /*
     * AC mod must start on 4k page boundary
     */

    if ( (unsigned long)acm_hdr & 0xfff ) {
        printk("AC mod base not 4K aligned (%p)\n", acm_hdr);
        return false;
    }
    printk("AC mod base alignment OK\n");

    /* AC mod size must:
     * - be multiple of 64
     * - greater than ???
     * - less than max supported size for this processor
     */

    if ( (size == 0) || ((size % 64) != 0) ) { 
        printk("AC mod size %x bogus\n", size);
        return false;
    }

    if ( get_parameters(&params) == -1 ) {
        printk("get_parameters() failed\n");
        return false;
    }

    if ( size > params.acm_max_size ) {
        printk("AC mod size too large: %x (max=%x)\n", size,
               params.acm_max_size);
        return false;
    }

    printk("AC mod size OK\n");

    /*
     * perform checks on AC mod structure
     */

    /* print it for debugging */
    print_acm_hdr(acm_hdr, "SINIT");

    /* entry point is offset from base addr so make sure it is within module */
    if ( acm_hdr->entry_point >= size ) {
        printk("AC mod entry (%08x) >= AC mod size (%08x)\n",
               acm_hdr->entry_point, size);
        return false;
    }

    if ( !acm_hdr->seg_sel           ||       /* invalid selector */
         (acm_hdr->seg_sel & 0x07)   ||       /* LDT, PL!=0 */
         (acm_hdr->seg_sel + 8 > acm_hdr->gdt_limit) ) {
        printk("AC mod selector [%04x] bogus\n", acm_hdr->seg_sel);
        return false;
    }

	return true;
}

/*
 * this must be done for each processor so that all have the same
 * memory types
 */
void set_mtrrs_for_acmod(acm_hdr_t *hdr)
{
    unsigned long eflags;
    unsigned long cr0, cr4;

    /*
     * need to do some things before we start changing MTRRs
     *
     * since this will modify some of the MTRRs, they should be saved first
     * so that they can be restored once the AC mod is done
     */

    /* disable interrupts */
    __save_flags(eflags);
    __cli();

    /* save CR0 then disable cache (CRO.CD=1, CR0.NW=0) */
    cr0 = read_cr0();
    write_cr0((cr0 & ~X86_CR0_NW) | X86_CR0_CD);

    /* flush caches */
    wbinvd();

    /* save CR4 and disable global pages (CR4.PGE=0) */
    cr4 = read_cr4();
    write_cr4(cr4 & ~X86_CR4_PGE);

    /* disable MTRRs */
    set_all_mtrrs(false);

    /*
     * now set MTRRs for AC mod and rest of memory
     */
    set_mem_type(hdr, hdr->size*4, MTRR_TYPE_WRBACK);

    /*
     * now undo some of earlier changes and enable our new settings
     */

    /* flush caches */
    wbinvd();

    /* enable MTRRs */
    set_all_mtrrs(true);

    /* restore CR0 (cacheing) */
    write_cr0(cr0);

    /* restore CR4 (global pages) */
    write_cr4(cr4);

    /* enable interrupts */
    __restore_flags(eflags);
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
