/*
 * paging_64.c: Enable 64-bit paging and jump to PE entry points
 */

#include <stdbool.h>
#include <types.h>
#include <compiler.h>
#include <printk.h>
#include <processor.h>
#include <tb_error.h>
#include <paging.h>
#include <misc.h>
#include <msr.h>
#include <string.h>
#include <uuid.h>
#include <loader.h>

#define __page __attribute__ ((__section__ (".bss.page_aligned"),aligned(4096)))

static uint64_t __page pml4[512];
static uint64_t __page pml3_low[512];
static uint64_t __page pml3_kernel[512];

static uint64_t __page pml2_low[512 * 4]; // Identity mapping of all memory < 4G
static uint64_t __page pml2_kernel[512];  // Mapping of the kernel's entry point

/* Private lanuch information structure */
struct pe_data {
    uint64_t entry;
    uint64_t rcx;
    uint64_t rdx;
};

/* Public structure provided to PE entry function */
struct tboot_table {
    char magic[8];
    uint64_t phys_start;
};

static struct pe_data pe_data;

static struct tboot_table tboot_table = {
    .magic = "TBOOT_PE"
};

static uint64_t mk_table(void* table)
{
    return ((uint64_t)(uint32_t)table) | _PAGE_PRESENT | _PAGE_RW | _PAGE_A;
}

static inline int pml4_slot(uint64_t addr)
{
    return (addr >> 39) & 0x1FF;
}

static inline int pml3_slot(uint64_t addr)
{
    return (addr >> 30) & 0x1FF;
}

static inline int pml2_slot(uint64_t addr)
{
    return (addr >> 21) & 0x1FF;
}

#define PML2_MASK (((1 << 21) - 1))

bool setup_pml4(uint64_t virtual_base, uint32_t load_addr, uint32_t load_size, uint64_t entry)
{
    uint64_t virtual_end = virtual_base + load_size;
    uint32_t pml2_start = pml2_slot(virtual_base);
    uint32_t pml2_slots = 1 + ((load_size - 1) >> 21);
    uint32_t i;

    if ( virtual_base < (1ULL << 39) ) {
        // This would make pml3_kernel and pml3_low overlap
        printk(TBOOT_ERR "Cannot map PE kernel below 512GB\n");
        return false;
    }

    if ( load_size >= (1 << 30) ) {
        // Requires more than one page for pml2_kernel
        printk(TBOOT_ERR "Virtual layouts larger than 1GB not supported\n");
        return false;
    }

    if ( virtual_base & PML2_MASK ) {
        printk(TBOOT_ERR "Virtual layouts must be 2MB-aligned\n");
        return false;
    }

    if ( load_addr & PML2_MASK ) {
        printk(TBOOT_ERR "Physical addresses must be 2MB-aligned\n");
        return false;
    }

    tboot_table.phys_start = load_addr;
    pe_data.entry = entry;

    // Always map the lower 4G as 1:1
    pml4[pml4_slot(0)] = mk_table(pml3_low);

    for( i = 0; i < 4; i++ )
        pml3_low[i] = mk_table(&pml2_low[i * 512]);

    for( i = 0; i < 512*4; i++ )
        pml2_low[i] = MAKE_TB_PDE(i << 21);

    /* Map the kernel's virtual address space.  If (slot) wraps around in the
     * loop below, there will be duplicate mappings created outside the
     * contiguous mapping, but that is harmless.
     */
    pml4[pml4_slot(virtual_base)] = mk_table(pml3_kernel);
    pml4[pml4_slot(virtual_end)] = mk_table(pml3_kernel);

    pml3_kernel[pml3_slot(virtual_base)] = mk_table(pml2_kernel);
    pml3_kernel[pml3_slot(virtual_end)] = mk_table(pml2_kernel);

    for( i = 0; i < pml2_slots; i++ ) {
        uint32_t slot = (pml2_start + i) & 0x1FF;
        uint32_t addr = load_addr + (i << 21);
        pml2_kernel[slot] = MAKE_TB_PDE(addr);
    }

    return true;
}

void jump_pe_image(void)
{
#define __BOOT_CS64    0x10
#define __BOOT_DS64    0x18
    static const uint64_t gdt_table[] __attribute__ ((aligned(16))) = {
        0,
        0,
        0x00af9b000000ffff,     /* cs64 */
        0x00cf93000000ffff      /* ds64 */
    };
    /* both 4G flat, CS: execute/read, DS: read/write */

    static struct __packed {
        uint16_t  length;
        uint32_t  table;
    } gdt_desc;

    gdt_desc.length = sizeof(gdt_table) - 1;
    gdt_desc.table = (uint32_t)&gdt_table;

    pe_data.rcx = (uint32_t)g_ldr_ctx->addr;
    pe_data.rdx = (uint32_t)&tboot_table;

    asm volatile(
    // Disable paging
     "mov %[cr0_nopg], %%eax\n"
     "mov %%eax, %%cr0\n"

    // Load the GDT that we'll use later to enter 64-bit mode
     "lgdtl %[gdt]\n"

    // Enable PAE
     "mov %[cr4], %%eax\n"
     "mov %%eax, %%cr4\n"

    // Load our page tables
     "mov %[pml4], %%eax\n"
     "mov %%eax, %%cr3\n"

    // Enable IA-32e mode (clobbers eax/edx)
     "mov %[efer], %%ecx\n"
     "rdmsr\n"
     "or %[lme], %%eax\n"
     "wrmsr\n"

    // Enable paging (now using the 1:1 map from pml2_low)
     "mov %[cr0], %%eax\n"
     "mov %%eax, %%cr0\n"

    // Jump to enter 64-bit mode (mov to cs)
     "ljmp %[cs64], $(1f)\n"
     ".code64\n"
     "1:\n"

    // Load the other segment registers
     "mov %[ds64], %%ecx\n"
     "mov %%ecx, %%ds\n"
     "mov %%ecx, %%es\n"
     "mov %%ecx, %%fs\n"
     "mov %%ecx, %%gs\n"
     "mov %%ecx, %%ss\n"

    // Align the stack
     "andq $-16, %%rsp\n"

    // Load 64-bit values into argument registers
     "movq 8(%%esi), %%rcx\n"
     "movq 16(%%esi), %%rdx\n"

    // Jump to the entry point
     "jmp *(%%esi)\n"

    // Reset the ASM dialect so that later GCC code is correct
     ".code32\n"
    ::
     [gdt] "m" (gdt_desc),
     [pml4] "ri" (&pml4[0]),
     [efer] "i" (MSR_EFER),
     [lme] "i" (1 << _EFER_LME),
     [cr0_nopg] "i" (CR0_PE | CR0_MP | CR0_NE),
     [cr0] "i" (CR0_PE | CR0_MP | CR0_NE | CR0_PG),
     [cr4] "i" (CR4_DE | CR4_PAE | CR4_MCE | CR4_FXSR | CR4_XMM | CR4_SMXE),
     [ds64] "i" (__BOOT_DS64),
     [cs64] "i" (__BOOT_CS64),
     "S" (&pe_data)
     : "eax");
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

