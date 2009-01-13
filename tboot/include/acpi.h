/*
 * acpi.h - ACPI Interface
 *
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 * Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#ifndef __ACPI_H__
#define __ACPI_H__

/* Root System Description Pointer (RSDP) */

typedef struct __packed {
    char        signature[8];
    uint8_t     checksum;
    char        oem_id[6];
    uint8_t     revision;
    uint32_t    rsdt_address;
} acpi_table_rsdp_t;

typedef struct __packed {
    char        signature[8];
    uint8_t     checksum;
    char        oem_id[6];
    uint8_t     revision;
    uint32_t    rsdt_address;
    uint32_t    length;
    uint64_t    xsdt_address;
    uint8_t     ext_checksum;
    uint8_t     reserved[3];
} acpi20_table_rsdp_t;

typedef struct __packed {
    uint8_t     type;
    uint8_t     length;
} acpi_table_entry_header_t;

typedef struct __packed {      /* ACPI common table header */
    char        signature[4];  /* ACPI signature (4 ASCII characters) */
    uint32_t    length;        /* Length of table, in bytes, including header */
    uint8_t     revision;      /* ACPI Specification minor version # */
    uint8_t     checksum;      /* To make sum of entire table == 0 */
    char        oem_id [6];    /* OEM identification */
    char        oem_table_id [8];       /* OEM table identification */
    uint32_t    oem_revision;           /* OEM revision number */
    char        asl_compiler_id [4];    /* ASL compiler vendor ID */
    uint32_t    asl_compiler_revision;  /* ASL compiler revision number */
} acpi_table_header_t;

/* Root System Description Table (RSDT) */

typedef struct __packed {
    acpi_table_header_t header;
    uint32_t            entry[8];
} acpi_table_rsdt_t;

/* Extended System Description Table (XSDT) */

typedef struct __packed {
    acpi_table_header_t header;
    uint64_t            entry[1];
} acpi_table_xsdt_t;

/* PCI MMCONFIG */

typedef struct __packed {
    acpi_table_header_t header;
    uint8_t             reserved[8];
    uint32_t            base_address;
    uint32_t            base_reserved;
} acpi_table_mcfg_t ;

/* Multiple APIC Description Table (MADT) */

typedef struct __packed {
    acpi_table_header_t header;
    uint32_t            lapic_address;
    struct {
        uint32_t        pcat_compat:1;
        uint32_t        reserved:31;
    } flags;
} acpi_table_madt_t;

enum acpi_madt_entry_id {
    ACPI_MADT_LAPIC = 0,
    ACPI_MADT_IOAPIC,
    ACPI_MADT_INT_SRC_OVR,
    ACPI_MADT_NMI_SRC,
    ACPI_MADT_LAPIC_NMI,
    ACPI_MADT_LAPIC_ADDR_OVR,
    ACPI_MADT_IOSAPIC,
    ACPI_MADT_LSAPIC,
    ACPI_MADT_PLAT_INT_SRC,
    ACPI_MADT_ENTRY_COUNT
};

typedef struct __packed {
    acpi_table_entry_header_t   header;
    uint8_t                     id;
    uint8_t                     reserved;
    uint32_t                    address;
    uint32_t                    global_irq_base;
} acpi_table_ioapic_t;

extern uint32_t get_acpi_mcfg_table(void);
extern uint32_t get_acpi_ioapic_table(void);

extern bool save_vtd_dmar_table(void);
extern bool restore_vtd_dmar_table(void);
extern bool remove_vtd_dmar_table(void);

extern void machine_sleep(const tboot_acpi_sleep_info *acpi_info);

#endif /* __ACPI_H__ */
