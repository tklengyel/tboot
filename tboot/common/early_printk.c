/*
 * early_printk.c: printk to serial for very early boot stages
 *
 * Copyright (c) 2006-2009, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <config.h>
#include <stdarg.h>
#include <types.h>
#include <stdbool.h>
#include <compiler.h>
#include <string.h>
#include <string2.h>
#include <misc.h>
#include <processor.h>
#include <spinlock.h>
#include <printk.h>
#include <uuid.h>
#include <tboot.h>
#include <cmdline.h>

DEFINE_SPINLOCK(print_lock);

uint8_t g_log_level = TBOOT_LOG_LEVEL_ALL; /* default is to print all */
uint8_t g_log_targets = TBOOT_LOG_TARGET_SERIAL; /* default vga logging targets */

/* memory logging */

/* memory-based serial log (ensure in .data section so that not cleared) */
__data tboot_log_t *g_log = NULL;

void early_memlog_init(void)
{
    if ( g_log == NULL ) {
        g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
        g_log->uuid = (uuid_t)TBOOT_LOG_UUID;
        g_log->curr_pos = 0;
    }

    /* initialize these post-launch as well, since bad/malicious values */
    /* could compromise environment */
    g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
    g_log->buf = (char *)g_log + sizeof(*g_log);
    g_log->max_size = TBOOT_SERIAL_LOG_SIZE - sizeof(*g_log);

    /* if we're calling this post-launch, verify that curr_pos is valid */
    if ( g_log->curr_pos > g_log->max_size )
        g_log->curr_pos = 0;
}

void early_memlog_write(const char *str, unsigned int count)
{
    if ( g_log == NULL || count > g_log->max_size )
        return;

    /* wrap to beginning if too big to fit */
    if ( g_log->curr_pos + count > g_log->max_size )
        g_log->curr_pos = 0;

    memcpy(&g_log->buf[g_log->curr_pos], str, count);
    g_log->curr_pos += count;

    /* if the string wasn't NULL-terminated, then NULL-terminate the log */
    if ( str[count-1] != '\0' )
        g_log->buf[g_log->curr_pos] = '\0';
    else {
        /* so that curr_pos will point to the NULL and be overwritten */
        /* on next copy */
        g_log->curr_pos--;
    }
}

/* serial logging */

/*
 * serial support from linux.../arch/x86_64/kernel/early_printk.c and
 * serial initialization support ported from xen drivers/char/ns16550.c
 */

#define XMTRDY          0x20

#define DLAB		0x80

#define TXR             0       /*  Transmit register (WRITE) */
#define RXR             0       /*  Receive register  (READ)  */
#define IER             1       /*  Interrupt Enable          */
#define IIR             2       /*  Interrupt ID              */
#define FCR             2       /*  FIFO control              */
#define LCR             3       /*  Line control              */
#define MCR             4       /*  Modem control             */
#define LSR             5       /*  Line Status               */
#define MSR             6       /*  Modem Status              */
#define DLL             0       /*  Divisor Latch Low         */
#define DLH             1       /*  Divisor latch High        */
#define DLM             0x01    /* divisor latch (ms) (DLAB=1) */

/* FIFO Control Register */
#define FCR_ENABLE      0x01    /* enable FIFO          */
#define FCR_CLRX        0x02    /* clear Rx FIFO        */
#define FCR_CLTX        0x04    /* clear Tx FIFO        */
#define FCR_DMA         0x10    /* enter DMA mode       */
#define FCR_TRG1        0x00    /* Rx FIFO trig lev 1   */
#define FCR_TRG4        0x40    /* Rx FIFO trig lev 4   */
#define FCR_TRG8        0x80    /* Rx FIFO trig lev 8   */
#define FCR_TRG14       0xc0    /* Rx FIFO trig lev 14  */

/* Line Control Register */
#define LCR_DLAB        0x80    /* Divisor Latch Access */

/* Modem Control Register */
#define MCR_DTR         0x01    /* Data Terminal Ready  */
#define MCR_RTS         0x02    /* Request to Send      */
#define MCR_OUT2        0x08    /* OUT2: interrupt mask */
#define MCR_LOOP        0x10    /* Enable loopback test mode */

/* These parity settings can be ORed directly into the LCR. */
#define PARITY_NONE     (0<<3)
#define PARITY_ODD      (1<<3)
#define PARITY_EVEN     (3<<3)
#define PARITY_MARK     (5<<3)
#define PARITY_SPACE    (7<<3)

/* Frequency of external clock source. This definition assumes PC platform. */
#define UART_CLOCK_HZ    1843200

/* LCR value macro */
#define TARGET_LCR_VALUE(d, s, p) ((d - 5) | ((s - 1) << 2) | p)

/* Highest BAUD */
#define TARGET_BAUD      115200

#define TBOOT_BAUD_AUTO (-1)

typedef struct {
    unsigned short io_base;
    unsigned int   baud;
    unsigned int   clock_hz;
    unsigned char  lcr;
} tboot_serial_t;

static tboot_serial_t g_serial_vals = {
    0x3f8,                              /* ttyS0 / COM1 */
    TARGET_BAUD,
    UART_CLOCK_HZ,
    TARGET_LCR_VALUE(8, 1, PARITY_NONE) /* default 8n1 LCR */
};

static int early_serial_putc(unsigned char ch)
{
    unsigned timeout = 0xffff;
    while ((inb(g_serial_vals.io_base + LSR) & XMTRDY) == 0 && --timeout)
        cpu_relax();
    outb(ch, g_serial_vals.io_base + TXR);
    return timeout ? 0 : -1;
}

void early_serial_write(const char *str, unsigned int count)
{
    while ((*str != '\0')&&(count-- > 0)) {
        /* write carriage return before newlines */
        if (*str == '\n')
            early_serial_putc('\r');
        early_serial_putc(*str);
        str++;
    }
}

void early_serial_init(void)
{
    unsigned char lcr;
    unsigned int  divisor;

    lcr = g_serial_vals.lcr;

    /* TBD: we should sanitize io_base? */

    /* No interrupts. */
    outb(0, g_serial_vals.io_base + IER);

    /* Line control and baud-rate generator. */
    outb(lcr | DLAB, g_serial_vals.io_base + LCR);

    if ( g_serial_vals.baud != TBOOT_BAUD_AUTO && g_serial_vals.baud != 0 ) {
        /* Baud rate specified: program it into the divisor latch. */
        divisor = g_serial_vals.clock_hz / (g_serial_vals.baud * 16);
        outb((char)divisor, g_serial_vals.io_base + DLL);
        outb((char)(divisor >> 8), g_serial_vals.io_base + DLM);
    }
    else {
        /* Baud rate already set: read it out from the divisor latch (to be
           consistent). */
        divisor  = inb(g_serial_vals.io_base + DLL);
        divisor |= inb(g_serial_vals.io_base + DLM) << 8;
        if ( divisor == 0 )
            g_serial_vals.baud = TARGET_BAUD;
        else
            g_serial_vals.baud = g_serial_vals.clock_hz / (divisor << 4);
    }

    outb(lcr, g_serial_vals.io_base + LCR);

    /* No flow ctrl: DTR and RTS are both wedged high to keep remote happy. */
    outb(MCR_DTR | MCR_RTS, g_serial_vals.io_base + MCR);

    /* Enable and clear the FIFOs. Set a large trigger threshold. */
    outb(FCR_ENABLE | FCR_CLRX | FCR_CLTX | FCR_TRG14, g_serial_vals.io_base +
         FCR);
}

/*
 * serial config parsing support ported from xen drivers/char/ns16550.c
 * Copyright (c) 2003-2005, K A Fraser
 */

static unsigned char parse_parity_char(int c)
{
    switch ( c )
    {
    case 'n':
        return PARITY_NONE;
    case 'o':
        return PARITY_ODD;
    case 'e':
        return PARITY_EVEN;
    case 'm':
        return PARITY_MARK;
    case 's':
        return PARITY_SPACE;
    }
    return 0;
}

static int check_existence(void)
{
    unsigned char status;

    /* Note really concerned with IER test */

    /*
     * Check to see if a UART is really there.
     * Use loopback test mode.
     */
    outb(MCR_LOOP | 0x0A, g_serial_vals.io_base + MCR);
    status = inb(g_serial_vals.io_base + MSR) & 0xF0;

    return (status == 0x90);
}

void early_serial_parse_port_config(const char *conf)
{
    unsigned char data_bits = 8, stop_bits = 1, parity;
    unsigned int baud;

    if ( strncmp(conf, "auto", 4) == 0 ) {
        g_serial_vals.baud = TBOOT_BAUD_AUTO;
        conf += 4;
    }
    else if ( (baud = (unsigned int)simple_strtoul(conf, (char **)&conf, 10))
              != 0 )
        g_serial_vals.baud = baud;

    if ( *conf == '/' ) {
        conf++;
        g_serial_vals.clock_hz = simple_strtoul(conf, (char **)&conf, 0) << 4;
    }

    if ( *conf != ',' )
        goto config_parsed;
    conf++;

    data_bits = (unsigned char)simple_strtoul(conf, (char **)&conf, 10);

    parity = parse_parity_char(*conf);
    if ( *conf != '\0' )
        conf++;

    stop_bits = (unsigned char)simple_strtoul(conf, (char **)&conf, 10);

    g_serial_vals.lcr = TARGET_LCR_VALUE(data_bits, stop_bits, parity);

    if ( *conf == ',' ) {
        conf++;
        g_serial_vals.io_base = (short)simple_strtoul(conf, (char **)&conf, 0);
        /* no irq, tboot not expecting Rx */
    }

config_parsed:
    /* Sanity checks - disable serial logging if input is invalid */
    if ( (g_serial_vals.baud != TBOOT_BAUD_AUTO) &&
         ((g_serial_vals.baud < 1200) || (g_serial_vals.baud > 115200)) )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;
    if ( (data_bits < 5) || (data_bits > 8) )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;
    if ( (stop_bits < 1) || (stop_bits > 2) )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;
    if ( g_serial_vals.io_base == 0 )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;
    if ( !check_existence() )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;
}

/* VGA logging */

/*
 * VGA support from linux.../arch/x86_64/kernel/early_printk-xen.c
 *
 * Simple VGA output
 */

#define VGABASE     0xb8000

static const int max_ypos = 25;
static const int max_xpos = 80;

void early_vga_write(const char *str, unsigned int count)
{
    static int current_ypos = 25;
    static __data int current_xpos = 0;
    char c;
    int  i, k, j;

    while ( ((c = *str++) != '\0') && (count-- > 0) ) {
        if ( current_ypos >= max_ypos ) {
            /* scroll 1 line up */
            for ( k = 1, j = 0; k < max_ypos; k++, j++ ) {
                for ( i = 0; i < max_xpos; i++ ) {
                    writew(readw(VGABASE+2*(max_xpos*k+i)),
                           VGABASE + 2*(max_xpos*j + i));
                }
            }
            for ( i = 0; i < max_xpos; i++ )
                writew(0x720, VGABASE + 2*(max_xpos*j + i));
            current_ypos = max_ypos-1;
        }
        if ( c == '\n' ) {
            current_xpos = 0;
            current_ypos++;
        } else if ( c != '\r' )  {
            writew(((0x7 << 8) | (unsigned short) c),
                   VGABASE + 2*(max_xpos*current_ypos +
                        current_xpos++));
            if ( current_xpos >= max_xpos ) {
                current_xpos = 0;
                current_ypos++;
            }
        }
    }
}

/* base logging */

#define WRITE_LOGS(s, n) \
if (g_log_targets & TBOOT_LOG_TARGET_VGA) early_vga_write(s, n); \
if (g_log_targets & TBOOT_LOG_TARGET_SERIAL) early_serial_write(s, n); \
if (g_log_targets & TBOOT_LOG_TARGET_MEMORY) early_memlog_write(s, n);

void early_printk(const char *fmt, ...)
{
    char buf[128];
    int n;
    va_list ap;
    static bool last_line_cr = true;

    if ( !g_log_level )
        return;

    memset(buf, '\0', sizeof(buf));
    va_start(ap, fmt);
    n = vscnprintf(buf, sizeof(buf), fmt, ap);
    spin_lock(&print_lock);
    /* prepend "TBOOT: " if the last line that was printed ended with a '\n' */
    if ( last_line_cr ) {
        WRITE_LOGS("TBOOT: ", 8);
    }

    last_line_cr = (n > 0 && buf[n-1] == '\n');
    WRITE_LOGS(buf, n);
    spin_unlock(&print_lock);
    va_end(ap);
}

void early_printk_init()
{
    /* parse loglvl from string to int */
    get_tboot_loglvl();

    /* parse logging targets and serial settings */
    get_tboot_log_targets();

    if ( g_log_targets & TBOOT_LOG_TARGET_MEMORY )
        early_memlog_init();
    if ( g_log_targets & TBOOT_LOG_TARGET_SERIAL )
        early_serial_init();
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
