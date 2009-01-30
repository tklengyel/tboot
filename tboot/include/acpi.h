/*
 * acpi.h - ACPI Interface
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
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


/*
 * Macros for moving data around to/from buffers that are possibly unaligned.
 * If the hardware supports the transfer of unaligned data, just do the store.
 * Otherwise, we have to move one byte at a time.
 */
#ifdef ACPI_BIG_ENDIAN
/*
 * Macros for big-endian machines
 */

/* These macros reverse the bytes during the move, converting little-endian to big endian */

	 /* Big Endian      <==        Little Endian */
	 /*  Hi...Lo                     Lo...Hi     */
#define ACPI_MOVE_64_TO_64(d,s)   \
 {((  u8 *)(void *)(d))[0] = ((u8 *)(void *)(s))[7];\
  ((  u8 *)(void *)(d))[1] = ((u8 *)(void *)(s))[6];\
  ((  u8 *)(void *)(d))[2] = ((u8 *)(void *)(s))[5];\
  ((  u8 *)(void *)(d))[3] = ((u8 *)(void *)(s))[4];\
  ((  u8 *)(void *)(d))[4] = ((u8 *)(void *)(s))[3];\
  ((  u8 *)(void *)(d))[5] = ((u8 *)(void *)(s))[2];\
  ((  u8 *)(void *)(d))[6] = ((u8 *)(void *)(s))[1];\
  ((  u8 *)(void *)(d))[7] = ((u8 *)(void *)(s))[0];}
#else
/*
 * Macros for little-endian machines
 */

#ifndef ACPI_MISALIGNMENT_NOT_SUPPORTED

/* The hardware supports unaligned transfers, just do the little-endian move */

/* 64-bit source, 64 destination */
#define ACPI_MOVE_64_TO_64(d,s)   \
 *(u64 *)(void *)(d) = *(u64 *)(void *)(s)

#else
/*
 * The hardware does not support unaligned transfers.  We must move the
 * data one byte at a time.  These macros work whether the source or
 * the destination (or both) is/are unaligned.  (Little-endian move)
 */

/* 64-bit source, 64 destination */
#define ACPI_MOVE_64_TO_64(d,s)   \
 {((  u8 *)(void *)(d))[0] = ((u8 *)(void *)(s))[0];\
  ((  u8 *)(void *)(d))[1] = ((u8 *)(void *)(s))[1];\
  ((  u8 *)(void *)(d))[2] = ((u8 *)(void *)(s))[2];\
  ((  u8 *)(void *)(d))[3] = ((u8 *)(void *)(s))[3];\
  ((  u8 *)(void *)(d))[4] = ((u8 *)(void *)(s))[4];\
  ((  u8 *)(void *)(d))[5] = ((u8 *)(void *)(s))[5];\
  ((  u8 *)(void *)(d))[6] = ((u8 *)(void *)(s))[6];\
  ((  u8 *)(void *)(d))[7] = ((u8 *)(void *)(s))[7];}
#endif
#endif



#define ACPI_INSERT_BITS(target,mask,source) \
    target = ((target & (~(mask))) | (source & mask))



typedef u32 acpi_status; /* All ACPI Exceptions */
#define AE_CODE_ENVIRONMENTAL    0x0000
#define AE_CODE_PROGRAMMER       0x1000
#define AE_OK              (acpi_status)0x0000
/* Environmental exceptions */
#define AE_ERROR           (acpi_status) (0x0001 | AE_CODE_ENVIRONMENTAL)
/* Programmer exceptions */
#define AE_BAD_PARAMETER   (acpi_status) (0x0001 | AE_CODE_PROGRAMMER)

#define ACPI_SUCCESS(a)    (!(a))
#define ACPI_FAILURE(a)    (a)



typedef u8 acpi_adr_space_type;
#define ACPI_ADR_SPACE_SYSTEM_MEMORY (acpi_adr_space_type)0
#define ACPI_ADR_SPACE_SYSTEM_IO     (acpi_adr_space_type)1



/*
 * Some ACPI registers have bits that must be ignored -- meaning that they
 * must be preserved.
 */
#define ACPI_PM1_STATUS_PRESERVED_BITS          0x0800  /* Bit 11 */
#define ACPI_PM1_CONTROL_PRESERVED_BITS         0x0200  /* Bit 9 (whatever) */

/*
 * Register IDs
 * These are the full ACPI registers
 */
#define ACPI_REGISTER_PM1_STATUS                0x01
#define ACPI_REGISTER_PM1_ENABLE                0x02
#define ACPI_REGISTER_PM1_CONTROL               0x03
#define ACPI_REGISTER_PM1A_CONTROL              0x04
#define ACPI_REGISTER_PM1B_CONTROL              0x05
#define ACPI_REGISTER_PM2_CONTROL               0x06
#define ACPI_REGISTER_PM_TIMER                  0x07
#define ACPI_REGISTER_PROCESSOR_BLOCK           0x08
#define ACPI_REGISTER_SMI_COMMAND_BLOCK         0x09


typedef unsigned short acpi_io_address;
typedef void * acpi_physical_address;


extern acpi_status machine_sleep(const tboot_acpi_sleep_info_t* acpi_sinfo);
extern void set_s3_resume_vector(const tboot_acpi_sleep_info_t* acpi_sinfo,
				 uint64_t resume_vector);

#endif /* __ACPI_H__ */
