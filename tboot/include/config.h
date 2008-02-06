/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/*
 * build/support flags
 */

/* TBD: remove this when only support BLK A1+ and no SDP3 */
#define CHIPSET_REVID_BUG

/* only enable this if VT-d has been applied to xen */
//#define VT_D


/* address tboot will execute (not necessarily load) at */
#define TBOOT_BASE_ADDR              0x1003000


/* address that tboot will do s3 resume at */
/* (must be in lower 1MB (real mode) and less than Xen trampoline @ 0x8c000) */
#define TBOOT_S3_WAKEUP_ADDR         0x8a000


/* these addrs must be in low memory so that they are mapped by the */
/* kernel at startup */

/* address/size for modified e820 table */
#define TBOOT_E820_COPY_ADDR         0x88000
#define TBOOT_E820_COPY_SIZE         0x01800

/* address/size for modified VMM/kernel command line */
#define TBOOT_KERNEL_CMDLINE_ADDR    (TBOOT_E820_COPY_ADDR + \
				      TBOOT_E820_COPY_SIZE)
#define TBOOT_KERNEL_CMDLINE_SIZE    0x0400


#ifndef NR_CPUS
#ifdef MAX_PHYS_CPUS
#define NR_CPUS     MAX_PHYS_CPUS
#else
#define NR_CPUS     16
#endif   /* MAX_PHYS_CPUS */
#endif   /* NR_CPUS */

#ifdef __ASSEMBLY__
#define ENTRY(name)                             \
  .globl name;                                  \
  .align 16,0x90;                               \
  name:
#endif

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS          "l"  /* Operation Suffix */
#define __OP          "e"  /* Operand Prefix */
#define __FIXUP_ALIGN ".align 4"
#define __FIXUP_WORD  ".long"

#ifndef EXPORT_SYMBOL
#define EXPORT_SYMBOL(var)
#endif

#define COMPILE_TIME_ASSERT( e )   \
    {                                                            \
        volatile int compile_time_assert_failed[ (e) ? 1 : -1];  \
        compile_time_assert_failed[0] = 0;                       \
    }

#define __data __attribute__ ((__section__ (".data")))

#endif /* __CONFIG_H__ */
