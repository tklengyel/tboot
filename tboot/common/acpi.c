/*
 *  from xen/arch/x86/acpi/boot.c
 *       drivers/acpi/tables.c
 *       drivers/acpi/hwregs.c
 *       drivers/acpi/osl.c
 *
 *  Copyright(c) 2008-2009 Intel Corporation. All rights reserved.
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Jun Nakajima <jun.nakajima@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <tboot.h>
#include <acpi.h>
#include <compiler.h>
#include <string2.h>
#include <misc.h>

#define ACPI_DMAR_TABLE_SIG "DMAR"
#define ACPI_MCFG_TABLE_SIG "MCFG"
#define ACPI_RSDP_TABLE_SIG "RSD PTR "
#define ACPI_XSDT_TABLE_SIG "XSDT"
#define ACPI_RSDT_TABLE_SIG "RSDT"
#define ACPI_MADT_TABLE_SIG "APIC"

/* used by various fns below */
static const tboot_acpi_sleep_info_t* g_acpi_sinfo;

static unsigned long acpi_scan_rsdp(unsigned long start, unsigned long length)
{
    unsigned long sig_len = sizeof(ACPI_RSDP_TABLE_SIG) - 1;

    /*
     * Scan all 16-byte boundaries of the physical memory region for the
     * RSDP signature.
     */
    for ( ; length > 0; length -= 16, start += 16 ) {
        if ( memcmp((void *)start, ACPI_RSDP_TABLE_SIG, sig_len) )
            continue;
        return start;
    }

    return 0;
}

static unsigned long acpi_find_rsdp(void)
{
    unsigned long rsdp_phys = 0;

    /*
     * Scan memory looking for the RSDP signature. First search EBDA (low
     * memory) paragraphs and then search upper memory (E0000-FFFFF).
     */
    rsdp_phys = acpi_scan_rsdp(0, 0x400);
    if ( !rsdp_phys )
        rsdp_phys = acpi_scan_rsdp(0xE0000, 0x20000);

    return rsdp_phys;
}

static int acpi_table_compute_checksum(const u8 *table_pointer,
                                       unsigned long length)
{
    unsigned long sum = 0;

    if ( !table_pointer || !length )
        return -1;

    while ( length-- )
        sum += *table_pointer++;

    return (sum & 0xFF);
}

static unsigned long acpi_get_table(const acpi_table_rsdp_t *rsdp,
                                    const char* sig)
{
    acpi_table_header_t *header = NULL;
    unsigned int i, sdt_count = 0;

    if ( !rsdp || !sig )
        return 0;

    /* First check XSDT (but only on ACPI 2.0-compatible systems) */
    if ( (rsdp->revision >= 2) &&
         (((acpi20_table_rsdp_t *)rsdp)->xsdt_address) ) {
        acpi_table_xsdt_t *xsdt = NULL;
        xsdt = (acpi_table_xsdt_t *)(uint32_t)
               (((acpi20_table_rsdp_t *)rsdp)->xsdt_address);
        header = &xsdt->header;

        if ( memcmp(header->signature, ACPI_XSDT_TABLE_SIG, 4) ) {
            printk("XSDT signature incorrect\n");
            return 0;
        }

        if ( acpi_table_compute_checksum((u8 *)header, header->length) ) {
            printk("Invalid XSDT checksum\n");
            return 0;
        }
        printk("Seek in XSDT...\n");
        sdt_count =
            (header->length - sizeof(acpi_table_header_t)) >> 3;

        for ( i = 0; i < sdt_count; i++ ) {
            header = (acpi_table_header_t *)(uint32_t)xsdt->entry[i];
            printk("entry[%d] sig = %c%c%c%c @ 0x%p\n", i,
                   header->signature[0], header->signature[1],
                   header->signature[2], header->signature[3],
		   header);
            if ( !memcmp(sig, &header->signature,
                         strnlen(sig, sizeof(header->signature))) )
                return (unsigned long)header;
        }
    }
    /* Then check RSDT */
    if ( rsdp->rsdt_address ) {
        acpi_table_rsdt_t *rsdt = NULL;
        rsdt = (acpi_table_rsdt_t *)rsdp->rsdt_address;
        header = &rsdt->header;

        if ( memcmp(header->signature, ACPI_RSDT_TABLE_SIG, 4) ) {
            printk("RSDT signature incorrect\n");
            return 0;
        }

        if ( acpi_table_compute_checksum((u8 *)header, header->length) ) {
            printk("Invalid RSDT checksum\n");
            return 0;
        }
        printk("Seek in RSDT...\n");
        sdt_count =
            (header->length - sizeof(acpi_table_header_t)) >> 2;

        for ( i = 0; i < sdt_count; i++ ) {
            header = (acpi_table_header_t *)rsdt->entry[i];
            printk("entry[%d] sig = %c%c%c%c @ 0x%p\n", i,
                   header->signature[0], header->signature[1],
                   header->signature[2], header->signature[3],
		   header);
            if ( !memcmp(sig, (char *)&header->signature,
                         strnlen(sig, sizeof(header->signature))) )
                return (unsigned long)header;
        }
    }
    printk("Not find required table entry.\n");
    return 0;
}

static uint32_t get_acpi_table(const char* sig)
{
    acpi_table_rsdp_t *rsdp = NULL;
    int result = 0;

    /* Locate the Root System Description Table (RSDP) */

    rsdp = (acpi_table_rsdp_t *)acpi_find_rsdp();
    if ( !rsdp ) {
        printk("Unable to locate RSDP\n");
        return 0;
    }

    printk("RSDP (v%3.3d %6.6s) @ 0x%p\n",
           rsdp->revision, rsdp->oem_id, (void *)rsdp);

    if ( rsdp->revision < 2 )
        result =
            acpi_table_compute_checksum((u8 *)rsdp,
                        sizeof(acpi_table_rsdp_t));
    else
        result =
            acpi_table_compute_checksum((u8 *)rsdp,
                        ((acpi20_table_rsdp_t *)
                         rsdp)->length);

    if ( result ) {
        printk("ERROR: Invalid checksum for RSDP\n");
        return 0;
    }

    /* Locate and map the System Description table (RSDT/XSDT) */

    return acpi_get_table(rsdp, sig);
}

static uint32_t get_acpi_table_entry(uint32_t start, uint32_t size, int type)
{
    acpi_table_entry_header_t *header = NULL;

    if ( start == 0 || size == 0 )
        return 0;

    while ( size > sizeof(acpi_table_entry_header_t) ) {
        header = (acpi_table_entry_header_t *)start;
        if ( header->length > size )
            break;

        if ( header->type == type )
            return start;

        size -= header->length;
        start += header->length;
    }

    return 0;
}

static uint32_t get_acpi_dmar_table(void)
{
    return get_acpi_table(ACPI_DMAR_TABLE_SIG);
}

static acpi_table_header_t *g_dmar_table;
static __data bool g_hide_dmar;

bool save_vtd_dmar_table(void)
{
    /* find DMAR table and save it */
    g_dmar_table = (acpi_table_header_t *) get_acpi_dmar_table();

    printk("DMAR table @ 0x%p saved.\n", g_dmar_table);
    return true;
}

bool restore_vtd_dmar_table(void)
{
    acpi_table_header_t *hdr;

    g_hide_dmar = false;

    /* find DMAR table first */
    hdr = (acpi_table_header_t *) get_acpi_dmar_table();
    if ( hdr != NULL ) {
        printk("DMAR table @ 0x%p is still there, skip restore step.\n", hdr);
        return true;
    }

    /* check saved DMAR table */
    if ( g_dmar_table == NULL ) {
        printk("No DMAR table saved, abort restore step.\n");
        return false;
    }

    /* restore DMAR if needed */
    memcpy(g_dmar_table->signature, ACPI_DMAR_TABLE_SIG, 4);

    /* find DMAR again to ensure restoring successfully */
    hdr = (acpi_table_header_t *) get_acpi_dmar_table();
    if ( hdr == NULL ) {
        printk("Failed to restore DMAR table, please FIX it.\n");
        return false;
    }

    /* checksum DMAR table */
    if ( acpi_table_compute_checksum((uint8_t *)hdr, hdr->length) ){
        printk("Checksum error for restored DMAR table, abort restore step.\n");
        return false;
    }

    /* need to hide DMAR table while resume from S3*/
    g_hide_dmar = true;
    printk("DMAR table @ 0x%p restored.\n", hdr);
    return true;
}

bool remove_vtd_dmar_table(void)
{
    acpi_table_header_t *hdr;

    /* check whether it is needed */
    if ( !g_hide_dmar ) {
        printk("No need to hide DMAR table.\n");
        return true;
    }

    /* find DMAR table */
    hdr = (acpi_table_header_t *) get_acpi_dmar_table();
    if ( hdr == NULL ) {
        printk("No DMAR table, skip remove step.\n");
        return true;
    }

    /* remove DMAR table */
    hdr->signature[0] = '\0';
    printk("DMAR table @ 0x%p removed.\n", hdr);
    return true;
}

uint32_t get_acpi_mcfg_table(void)
{
    return get_acpi_table(ACPI_MCFG_TABLE_SIG);
}

uint32_t get_acpi_ioapic_table(void)
{
    acpi_table_madt_t *madt;
    madt = (acpi_table_madt_t *)get_acpi_table(ACPI_MADT_TABLE_SIG);

    if ( madt == 0 ) {
        printk("Unable to locate madt table\n");
        return 0;
    }

    return get_acpi_table_entry(
                (uint32_t)madt + sizeof(acpi_table_madt_t),
                madt->header.length - sizeof(acpi_table_madt_t),
                ACPI_MADT_IOAPIC);
}

#define ACPI_BITMASK_WAKE_STATUS                0x8000
#define ACPI_BITPOSITION_WAKE_STATUS            0x0F

static acpi_status acpi_read_port(acpi_io_address port, u32* value, u32 width)
{
    if ( !value )
        return AE_ERROR;

    *value = 0;
    if ( width <= 8 )
        *(u8 *)value = inb(port);
    else if ( width <= 16 )
        *(u16 *)value = inw(port);
    else if ( width <= 32 )
        *(u32 *)value = in(port);
    else
        return AE_ERROR;

    return AE_OK;
}

static acpi_status acpi_write_port(acpi_io_address port, u32 value, u32 width)
{
    switch ( width ) {
    case 8:
        outb(value, port);
        break;
    case 16:
        outw(value, port);
        break;
    case 32:
        out(value, port);
        break;
    default:
        return AE_ERROR;
    }

    return AE_OK;
}

static acpi_status
acpi_read_memory(acpi_physical_address addr, u32* value, u32 width)
{
    if ( !value )
        return AE_ERROR;

    *value = 0;
    if ( width <= 8 )
        *(u8 *)value = readb(addr);
    else if ( width <= 16 )
        *(u16 *)value = readw(addr);
    else if ( width <= 32 )
        *(u32 *)value = readl(addr);
    else
        return AE_ERROR;

    return AE_OK;
}

static acpi_status
acpi_write_memory(acpi_physical_address addr, u32 value, u32 width)
{
    switch ( width ) {
    case 8:
        writeb(value, addr);
        break;
    case 16:
        writew(value, addr);
        break;
    case 32:
        writel(value, addr);
        break;
    default:
        return AE_ERROR;
    }

    return AE_OK;
}

static acpi_status
acpi_hw_low_level_read(u32 width, u32* value,
		       const tboot_acpi_generic_address_t* reg)
{
    u64 address;
    acpi_status status;

    /*
     * Must have a valid pointer to a GAS structure, and
     * a non-zero address within. However, don't return an error
     * because the PM1A/B code must not fail if B isn't present.
     */
    if ( !reg )
        return AE_OK;

    /* Get a local copy of the address. Handles possible alignment issues */
    ACPI_MOVE_64_TO_64(&address, &reg->address);
    if ( !address )
        return AE_OK;

    *value = 0;
    switch ( reg->space_id ) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
        status = acpi_read_memory(
                       (acpi_physical_address)(unsigned long)address,
                       value, width);
        break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
        status = acpi_read_port((acpi_io_address)address,
                                value, width);
        break;
    default:
        return AE_BAD_PARAMETER;
    }

    return status;
}

static acpi_status
acpi_hw_low_level_write(u32 width, u32 value,
			const tboot_acpi_generic_address_t* reg)
{
    u64 address;
    acpi_status status;

    /*
     * Must have a valid pointer to a GAS structure, and
     * a non-zero address within. However, don't return an error
     * because the PM1A/B code must not fail if B isn't present.
     */
    if ( !reg )
        return AE_OK;

    /* Get a local copy of the address. Handles possible alignment issues */
    ACPI_MOVE_64_TO_64(&address, &reg->address);
    if ( !address )
        return AE_OK;

    switch ( reg->space_id ) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
        status = acpi_write_memory(
                       (acpi_physical_address)(unsigned long)address,
                       value, width);
        break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
        status = acpi_write_port((acpi_io_address)address,
                                 value, width);
        break;
    default:
        return AE_BAD_PARAMETER;
    }

    return status;
}

static acpi_status
acpi_hw_register_read(u32 register_id, u32* value)
{
    u32 value1 = 0;
    u32 value2 = 0;
    acpi_status status;

    if ( !value )
        return AE_ERROR;

    switch ( register_id ) {
    case ACPI_REGISTER_PM1_STATUS:    /* 16-bit access */
        status = acpi_hw_low_level_read(16, &value1,
					&g_acpi_sinfo->pm1a_evt_blk);
        if ( ACPI_FAILURE(status) )
            goto exit;
        /* PM1B is optional */
        status = acpi_hw_low_level_read(16, &value2,
					&g_acpi_sinfo->pm1b_evt_blk);
        value1 |= value2;
        break;

    case ACPI_REGISTER_PM1_CONTROL:    /* 16-bit access */
        status = acpi_hw_low_level_read(16, &value1,
					&g_acpi_sinfo->pm1a_cnt_blk);
        if ( ACPI_FAILURE(status) )
            goto exit;
        status = acpi_hw_low_level_read(16, &value2,
					&g_acpi_sinfo->pm1b_cnt_blk);
        value1 |= value2;
        break;
    default:
        status = AE_BAD_PARAMETER;
        break;
    }

exit:
    if ( ACPI_SUCCESS(status) )
        *value = value1;

    return status;
}

static acpi_status
acpi_hw_register_write(u32 register_id, u32 value)
{
    u32 value1 = 0;
    acpi_status status;

    switch ( register_id ) {
    case ACPI_REGISTER_PM1_STATUS:    /* 16-bit access */
        /* Perform a read first to preserve certain bits (per ACPI spec) */
        status = acpi_hw_register_read(ACPI_REGISTER_PM1_STATUS, &value1);
        if ( ACPI_FAILURE(status) )
            goto exit;
        /* Insert the bits to be preserved */
        ACPI_INSERT_BITS(value, ACPI_PM1_STATUS_PRESERVED_BITS, value1);
        /* Now we can write the data */
        status  = acpi_hw_low_level_write(16, value,
                   &g_acpi_sinfo->pm1a_evt_blk);
        if ( ACPI_FAILURE(status) )
            goto exit;
        /* PM1B is optional */
        status = acpi_hw_low_level_write(16, value,
                   &g_acpi_sinfo->pm1b_evt_blk);
        break;
    case ACPI_REGISTER_PM1_CONTROL:    /* 16-bit access */
        /* Perform a read first to preserve certain bits (per ACPI spec) */
        status  = acpi_hw_register_read(ACPI_REGISTER_PM1_CONTROL, &value1);
        if ( ACPI_FAILURE(status) )
            goto exit;
        /* Insert the bits to be preserved */
        ACPI_INSERT_BITS(value, ACPI_PM1_CONTROL_PRESERVED_BITS, value1);
        /* Now we can write the data */
        status = acpi_hw_low_level_write(16, value,
                  &g_acpi_sinfo->pm1a_cnt_blk);
        if ( ACPI_FAILURE(status) )
            goto exit;
        status = acpi_hw_low_level_write(16, value,
                  &g_acpi_sinfo->pm1b_cnt_blk);
        break;
    case ACPI_REGISTER_PM1A_CONTROL:    /* 16-bit access */
        status = acpi_hw_low_level_write(16, value,
                  &g_acpi_sinfo->pm1a_cnt_blk);
        break;
    case ACPI_REGISTER_PM1B_CONTROL:    /* 16-bit access */
        status = acpi_hw_low_level_write(16, value,
                  &g_acpi_sinfo->pm1b_cnt_blk);
        break;
    default:
        status = AE_BAD_PARAMETER;
        break;
    }

exit:
    return status;
}

static int acpi_get_wake_status(void)
{
    uint32_t val;
    acpi_status status;

    /* Wake status is the 15th bit of PM1 status register. (ACPI spec 3.0) */
    status = acpi_hw_register_read(ACPI_REGISTER_PM1_STATUS, &val);
    if ( ACPI_FAILURE(status) )
        return 0;

    val &= ACPI_BITMASK_WAKE_STATUS;
    val >>= ACPI_BITPOSITION_WAKE_STATUS;
    return val;
}

acpi_status machine_sleep(const tboot_acpi_sleep_info_t* acpi_sinfo)
{
    acpi_status status;

    wbinvd();

    /* set for use by various ACPI fns above */
    g_acpi_sinfo = acpi_sinfo;

    status = acpi_hw_register_write(ACPI_REGISTER_PM1A_CONTROL,
                                    g_acpi_sinfo->pm1a_cnt_val);
    if ( ACPI_FAILURE(status) )
        return AE_ERROR;

    if ( g_acpi_sinfo->pm1b_cnt_blk.address ) {
        status = acpi_hw_register_write(ACPI_REGISTER_PM1B_CONTROL,
                                        g_acpi_sinfo->pm1b_cnt_val);
        if ( ACPI_FAILURE(status) )
            return AE_ERROR;
    }

    /* Wait until we enter sleep state; we should never return to here */
    while ( !acpi_get_wake_status() )
        continue;

    return AE_OK;
}

void set_s3_resume_vector(const tboot_acpi_sleep_info_t* acpi_sinfo,
                          uint64_t resume_vector)
{
    if ( acpi_sinfo->vector_width <= 32 )
        *(uint32_t *)(uintptr_t)acpi_sinfo->wakeup_vector =
                                    (uint32_t)resume_vector;
    else
        *(uint64_t *)(uintptr_t)acpi_sinfo->wakeup_vector =
                                    (uint64_t)resume_vector;
    printk("kernel S3 resume vector: 0x%Lx\n", resume_vector);
    printk("wakeup_vector: 0x%Lx\n", acpi_sinfo->wakeup_vector);
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
