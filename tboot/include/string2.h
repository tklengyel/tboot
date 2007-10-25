#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <types.h>	/* for size_t */

/*
 * Include machine specific inline routines
 */
#include <string.h>

extern size_t strnlen(const char *,size_t);

extern size_t strlen(const char * s);

extern void * memmove(void *,const void *,size_t);

#endif /* _LINUX_STRING_H_ */
