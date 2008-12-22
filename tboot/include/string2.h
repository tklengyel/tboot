#ifndef _LINUX_STRING_H_
#define _LINUX_STRING_H_

#include <types.h>	/* for size_t */

/*
 * Include machine specific inline routines
 */
#include <string.h>

extern int strcmp(const char *, const char *);

extern int strncmp(const char *, const char *, size_t);

extern char * strchr(const char *, int);

extern size_t strnlen(const char *, size_t);

extern size_t strlen(const char * s);

extern size_t strncpy(char *, const char *, size_t);

extern size_t strncat(char *, const char *, size_t);

extern void * memmove(void *, const void *, size_t);

#endif /* _LINUX_STRING_H_ */
