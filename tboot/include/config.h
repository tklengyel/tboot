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

/* address that tboot will execute at */
#define TBOOT_BASE_ADDR         0x60000

/* address that tboot will do s3 resume at */
#define TBOOT_S3_WAKEUP_ADDR    0x8a000

#ifdef MAX_PHYS_CPUS
#define NR_CPUS     MAX_PHYS_CPUS
#else
#define NR_CPUS     16
#endif

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

#define EXPORT_SYMBOL(var)

#define COMPILE_TIME_ASSERT( e )   \
    {                                                            \
        volatile int compile_time_assert_failed[ (e) ? 1 : -1];  \
        compile_time_assert_failed[0] = 0;                       \
    }

#endif /* __CONFIG_H__ */
