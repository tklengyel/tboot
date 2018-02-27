/*
 * pe.c: support functions for manipulating PE binaries
 */

#include <config.h>
#include <stdbool.h>
#include <types.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <uuid.h>
#include <loader.h>
#include <e820.h>

extern loader_ctx *g_ldr_ctx;
bool setup_pml4(uint64_t virtual_base, uint32_t load_addr, uint32_t load_size, uint64_t entry);

struct PE_DOS_Header {
    uint16_t signature;
    uint16_t lastsize;
    uint16_t nblocks;
    uint16_t nreloc;
    uint16_t hdrsize;
    uint16_t minalloc;
    uint16_t maxalloc;
    uint16_t ss;
    uint16_t sp;
    uint16_t checksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t relocpos;
    uint16_t noverlay;
    uint16_t reserved1[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved2[10];
    uint32_t e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
};

struct PE_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct PE_COFFHeader {
    uint32_t signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;

    uint16_t opt_header[0];
};

struct PEOptHeader64 {
    uint16_t signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. 
    uint8_t MajorLinkerVersion; 
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;  //The RVA of the code entry point
    uint32_t BaseOfCode;
    /*The next 21 fields are an extension to the COFF optional header format*/
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t Checksum;
    uint16_t Subsystem;
    uint16_t DLLCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct PE_data_directory DataDirectory[16];
};

struct PE_SectionHeader {
  char     Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

#define PE_SECTION_CODE 0x00000020
#define PE_SECTION_DATA 0x00000040
#define PE_SECTION_BSS  0x00000080

#define PE_SECTION_LOAD (PE_SECTION_CODE | PE_SECTION_DATA | PE_SECTION_BSS)

bool is_pe_image(const void *image, size_t size)
{
    const struct PE_DOS_Header *dos_hdr = image;
    const struct PE_COFFHeader *pe_hdr;

    /* check size */
    if ( sizeof(struct PE_DOS_Header) > size ) {
        printk(TBOOT_ERR"Error: Image size is smaller than PE header size.\n");
        return false;
    }

    if ( dos_hdr->signature != ('M' | ('Z' << 8)) ) {
        printk(TBOOT_WARN"PE DOS magic number not matched, image is not PE format.\n");
        return false;
    }

    if ( dos_hdr->e_lfanew + sizeof(struct PE_COFFHeader) > size ) {
        printk(TBOOT_ERR"Error: Image size is smaller than COFF header.\n");
        return false;
    }

    pe_hdr = image + dos_hdr->e_lfanew;

    if ( pe_hdr->signature != ('P' | ('E' << 8)) ) {
        printk(TBOOT_WARN"PE magic number not matched, image is not PE format.\n");
        return false;
    }

    if ( pe_hdr->Machine == 0x8664 &&
         pe_hdr->SizeOfOptionalHeader == sizeof(struct PEOptHeader64) &&
         pe_hdr->opt_header[0] == 523 ) {

        return true;
    }

    printk(TBOOT_WARN"PE COFF header is not a 64-bit PE.\n");
    return false;
}

bool expand_pe_image(const void *image, loader_ctx *lctx)
{
    const void* ptr = image;
    const struct PE_DOS_Header *dos_hdr = image;
    const struct PE_COFFHeader *pe_hdr;
    const struct PEOptHeader64 *pe64;
    const struct PE_SectionHeader *section;
    int i;
    uint32_t image_max = 0; // size when expanded
    uint32_t load_base;
    uint64_t entry, ram_base, ram_size;
     
    ptr += dos_hdr->e_lfanew;
    pe_hdr = ptr;
    ptr += sizeof(struct PE_COFFHeader);
    pe64 = ptr;
    ptr += sizeof(*pe64);
    section = ptr;

    entry = pe64->AddressOfEntryPoint;
    entry += pe64->ImageBase;

    for( i = 0; i < pe_hdr->NumberOfSections; i++ ) {
        uint32_t attrs = section[i].Characteristics;

        if ( attrs & PE_SECTION_LOAD ) {
            uint32_t start = section[i].VirtualAddress;
            uint32_t end = start + section[i].VirtualSize;
            if ( image_max < end )
                image_max = end; 
        }
    }

    // Find a suitable region to expand the PE, and use the top

    uint32_t limit = get_lowest_mod_start(lctx);

    get_highest_sized_ram(image_max + (1 << 21), (u32)limit,
                          &ram_base, &ram_size);

    if ( ram_size < image_max ) {
        printk(TBOOT_ERR"Not enough memory to load kernel.\n");
        return false;
    }

    if ( ram_base + ram_size > (u32)image )
        load_base = (u32)image - image_max;
    else
        load_base = ram_base + ram_size - image_max;

    // Round load_base down to the nearest 2MB; this is safe because we
    // requested 2MB more than we needed
    load_base &= ~((1 << 21) - 1);

    printk(TBOOT_INFO"Loading PE at %x (%llx %llx)\n", load_base, ram_base, ram_size);

    for( i = 0; i < pe_hdr->NumberOfSections; i++ ) {
        uint32_t attrs = section[i].Characteristics;

        if ( attrs & PE_SECTION_BSS ) {
            uint32_t dest = load_base + section[i].VirtualAddress;
            memset((void*)dest, 0, section[i].VirtualSize);
        } else if ( attrs & PE_SECTION_LOAD ) {
            const void* src = image + section[i].PointerToRawData;
            uint32_t dest = load_base + section[i].VirtualAddress;
            memcpy((void*)dest, src, section[i].VirtualSize);
        }
    }

    return setup_pml4(pe64->ImageBase, load_base, image_max, entry);
}
