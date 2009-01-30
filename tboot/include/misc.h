#ifndef __MISC_H__
#define __MISC_H__

/*
 * from system.h
 */

#define wbinvd() \
	__asm__ __volatile__ ("wbinvd": : :"memory");

#define __save_flags(x)		__asm__ __volatile__("pushfl ; popl %0":"=g" (x): /* no input */)
#define __restore_flags(x) 	__asm__ __volatile__("pushl %0 ; popfl": /* no output */ :"g" (x):"memory", "cc")
#define __cli() 		__asm__ __volatile__("cli": : :"memory")

/*
 * from x86/bitops.h
 */

/**
 * fls - find last bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 */
static inline int fls(unsigned long x)
{
  long r;

  __asm__("bsr %1,%0\n\t"
                "jnz 1f\n\t"
                "mov $-1,%0\n"
	  "1:" : "=r" (r) : "rm" (x));
  return (int)r+1;
}

static inline unsigned char inb(unsigned short port)
{
    unsigned char _v;

    __asm__ __volatile__ ("inb %w1, %0"
                          : "=a" (_v) : "Nd" (port));

    return _v;
}

static inline void outb(unsigned char value, unsigned short port)
{
    __asm__ __volatile__ ("outb %b0, %w1"
                          : : "a" (value), "Nd" (port));
}

static inline unsigned short inw(unsigned short port)
{
    unsigned short _v;

    __asm__ __volatile__ ("inw %w1, %w0"
                          : "=a" (_v) : "Nd" (port));

    return _v;
}

static inline void outw(unsigned short value, unsigned short port)
{
    __asm__ __volatile__ ("outw %w0, %w1"
                          : : "a" (value), "Nd" (port));
}

static inline unsigned int in(unsigned short port)
{
    unsigned int _v;

    __asm__ __volatile__ ("in %w1, %0"
                          : "=a" (_v) : "Nd" (port));

    return _v;
}

static inline void out(unsigned int value, unsigned short port)
{
    __asm__ __volatile__ ("out %0, %w1"
                          : : "a" (value), "Nd" (port));
}
/*
 * from io.h
 */

#define readb(x)  (*(volatile char *)(x))
#define readw(x)  (*(volatile short *)(x))
#define readl(x)  (*(volatile int *)(x))
#define writeb(d,x) (*(volatile char *)(x) = (d))
#define writew(d,x) (*(volatile short *)(x) = (d))
#define writel(d,x) (*(volatile int *)(x) = (d))

/*
 * from lib.h
 */
#include <stdarg.h>

#define BUG() /**/
#define BUG_ON(_p) do { if (_p) BUG(); } while ( 0 )

/* vsprintf.c */
unsigned long simple_strtoul(const char *,char **,unsigned int);
long simple_strtol(const char *,char **,unsigned int);
extern int sprintf(char * buf, const char * fmt, ...)
    __attribute__ ((format (printf, 2, 3)));
extern int vsprintf(char *buf, const char *, va_list)
    __attribute__ ((format (printf, 2, 0)));
extern int snprintf(char * buf, size_t size, const char * fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)));
extern int scnprintf(char * buf, size_t size, const char * fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
extern int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)));

/*
 * original
 */
#define ARRAY_SIZE(a)     (sizeof(a) / sizeof((a)[0]))

/* from misc.c */
extern void print_hex(const char *prefix, const uint8_t *str, size_t n);

/* from gcc gmacros.h */
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))


#endif   /*  __MISC_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
