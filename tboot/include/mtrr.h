#ifndef __ASM_X86_MTRR_H__
#define __ASM_X86_MTRR_H__

#include <config.h>

/* These are the region types. They match the architectural specification. */
#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7

#endif /* __ASM_X86_MTRR_H__ */
