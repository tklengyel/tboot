#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <ctype.h>
#include <printk.h>
#include <compiler.h>
#include <processor.h>
#include <msr.h>
#include <misc.h>


/* for include/ctype.h */
const unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,         /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                    /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                        /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                        /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                        /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,      /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                        /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,      /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                        /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,   /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,       /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,       /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,       /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,       /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};      /* 240-255 */


void print_hex(const char *prefix, const void *data, size_t n)
{
    for ( unsigned int i = 0; i < n; i++ ) {
        if ( i % 16 == 0 && prefix != NULL )
            printk("\n%s", prefix);
		printk("%02x ", *(uint8_t *)data++);
    }
    printk("\n");
}

bool multiply_overflow_u32(const uint32_t x, const uint32_t y)
{
    return (x > 0) ? ((((uint32_t)(~0))/x) < y) : false;
}

bool plus_overflow_u32(const uint32_t x, const uint32_t y)
{
    return (x + y) < x;
}

bool plus_overflow_u64(const uint64_t x, const uint64_t y)
{
    return (x + y) < x;
}

bool multiply_overflow_ul(const unsigned long x, const unsigned long y)
{
    return (x > 0) ? ((((unsigned long)(~0))/x) < y) : false;
}

bool plus_overflow_ul(const unsigned long x, const unsigned long y)
{
    return (x + y) < x;
}

static bool g_calibrated = false;
static uint64_t g_ticks_per_sec;

static void wait_tsc_uip(void)
{
    outb(0x0a, 0x70);     /* status A */
    /* wait for UIP to be set */
    do {
        cpu_relax();
    } while ( !(inb(0x71) & 0x80) );
    /* now wait for it to clear */
    do {
        cpu_relax();
    } while ( inb(0x71) & 0x80 );
}

static bool calibrate_tsc(void)
{
    if ( g_calibrated )
        return false;

    /* wait for UIP to be de-asserted */
    wait_tsc_uip();

    /* get starting TSC val */
    uint64_t rtc_start;
    rdtscll(rtc_start);

    /* wait for seconds to be updated */
    wait_tsc_uip();

    uint64_t rtc_end;
    rdtscll(rtc_end);

    /* # ticks in 1 sec */
    g_ticks_per_sec = rtc_end - rtc_start;

    return true;
}

void delay(int secs)
{
    /* calibration will take 1sec */
    if ( calibrate_tsc() )
        secs -= 1;

    if ( secs <= 0 )
        return;

    uint64_t rtc;
    rdtscll(rtc);

    uint64_t end_ticks = rtc + secs * g_ticks_per_sec;
    while ( rtc < end_ticks ) {
        cpu_relax();
        rdtscll(rtc);
    }
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
