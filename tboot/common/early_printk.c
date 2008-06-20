/*
 * early_printk.c: printk to serial for very early boot stages
 *
 * Copyright (c) 2006-2007, Intel Corporation
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

DEFINE_SPINLOCK(print_lock);

/* memory-based serial log */
tboot_log_t *g_log = NULL;

void init_log(void)
{
#ifdef MEM_LOGGING
    g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
#endif

    if ( g_log == NULL )
        return;

    /* only initialize first time (i.e. not after launch) */
    if ( !are_uuids_equal(&(g_log->uuid), &((uuid_t)TBOOT_LOG_UUID)) ) {
        g_log->uuid = (uuid_t)TBOOT_LOG_UUID;
        g_log->curr_pos = 0;
    }
    g_log->buf = (char *)(TBOOT_SERIAL_LOG_ADDR + sizeof(*g_log));
    g_log->max_size = TBOOT_SERIAL_LOG_SIZE - sizeof(*g_log);

    /* if we're calling this post-launch, verify that curr_pos is valid */
    if ( g_log->curr_pos > g_log->max_size )
        g_log->curr_pos = 0;
}

static void write_log(const char *s, unsigned int n)
{
    if ( g_log == NULL )
        return;

    if ( n > g_log->max_size )
        return;

    /* wrap to beginning if too big to fit */
    if ( g_log->curr_pos + n > g_log->max_size )
        g_log->curr_pos = 0;

    memcpy(&g_log->buf[g_log->curr_pos], s, n);
    g_log->curr_pos += n;

    /* if the string wasn't NULL-terminated, then NULL-terminate the log */
    if ( s[n-1] != '\0' )
        g_log->buf[g_log->curr_pos] = '\0';
    else {
        /* so that curr_pos will point to the NULL and be overwritten */
        /* on next copy */
        g_log->curr_pos--;
    }
}

void print_log(void)
{
    printk("g_log:\n");
    if ( g_log == NULL )
        printk("\t *** memory logging disabled ***\n");
    else {
        printk("\t uuid="); print_uuid(&g_log->uuid); printk("\n");
        printk("\t max_size=%x\n", g_log->max_size);
        printk("\t curr_pos=%x\n", g_log->curr_pos);
    }
}


/*
 * serial support from linux.../arch/x86_64/kernel/early_printk.c
 *
 * this code does not initialize the serial port and assumes COM1, so
 * it will only display if GRUB has been configured for output to COM1
 */

#define early_serial_base    0x3f8      /* ttyS0 */

#define XMTRDY          0x20

#define DLAB		    0x80

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

int loglevel = 1; /* default is to print all */

static int early_serial_putc(unsigned char ch) 
{ 
    unsigned timeout = 0xffff; 
    while ((inb(early_serial_base + LSR) & XMTRDY) == 0 && --timeout) 
        cpu_relax();
    outb(ch, early_serial_base + TXR);
    return timeout ? 0 : -1;
} 

static void early_serial_write(const char *s, unsigned int n)
{
    while (*s && n-- > 0) { 
        early_serial_putc(*s); 
        if (*s == '\n') 
            early_serial_putc('\r'); 
        s++; 
    } 
}

void early_serial_printk(const char *fmt, ...)
{
	char buf[128];
	int n;
	va_list ap;
    static bool last_line_cr = true;

    if ( !loglevel )
        return;

    memset(buf, '\0', sizeof(buf));
	va_start(ap, fmt);
    n = vscnprintf(buf, sizeof(buf), fmt, ap);
    spin_lock(&print_lock);
    /* prepend "TBOOT: " if the last line that was printed ended with a '\n' */
    if ( last_line_cr ) {
        early_serial_write("TBOOT: ", 8);
        write_log("TBOOT: ", 8);
    }
    last_line_cr = (n > 0 && buf[n-1] == '\n');
	early_serial_write(buf, n);
    write_log(buf, n);
    spin_unlock(&print_lock);
	va_end(ap);
}


/*
 * serial initialization support ported from xen drivers/char/ns16550.c
 * Copyright (c) 2003-2005, K A Fraser
 */
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

/* These parity settings can be ORed directly into the LCR. */
#define PARITY_NONE     (0<<3)
#define PARITY_ODD      (1<<3)
#define PARITY_EVEN     (3<<3)
#define PARITY_MARK     (5<<3)
#define PARITY_SPACE    (7<<3)

/* Frequency of external clock source. This definition assumes PC platform. */
#define UART_CLOCK_HZ   1843200

#define TARGET_LCR_VALUE    ((8 - 5) | ((1 - 1) << 2) | PARITY_NONE)
#define TARGET_BAUD         115200

void early_serial_init(void)
{
    unsigned char lcr;
    unsigned int  divisor;

    lcr = TARGET_LCR_VALUE;

    /* No interrupts. */
    outb(0, early_serial_base + IER);

    /* Line control and baud-rate generator. */
    outb(lcr | DLAB, early_serial_base + LCR);
    
    /* Baud rate specified: program it into the divisor latch. */
    divisor = UART_CLOCK_HZ / (TARGET_BAUD * 16);
    outb((char)divisor, early_serial_base + DLL);
    outb((char)(divisor >> 8), early_serial_base + DLM);
    
    outb(lcr, early_serial_base + LCR);

    /* No flow ctrl: DTR and RTS are both wedged high to keep remote happy. */
    outb(MCR_DTR | MCR_RTS, early_serial_base + MCR);

    /* Enable and clear the FIFOs. Set a large trigger threshold. */
    outb(FCR_ENABLE | FCR_CLRX | FCR_CLTX | FCR_TRG14, early_serial_base + FCR);
}

/*
 * serial support from linux.../arch/x86_64/kernel/early_printk-xen.c
 *
 * Simple VGA output
 */

#define VGABASE     0xb8000

#define readw(x) (*(volatile unsigned short *)(x))
#define writew(d,x) (*(volatile unsigned short *)(x) = (d))

static const int max_ypos = 25;
static const int max_xpos = 80;

void early_vga_printk(const char *str)
{
    static int current_ypos = 25;
    static __data int current_xpos = 0;
    char c;
    int  i, k, j;

    while ((c = *str++) != '\0') {
        if (current_ypos >= max_ypos) {
            /* scroll 1 line up */
            for (k = 1, j = 0; k < max_ypos; k++, j++) {
                for (i = 0; i < max_xpos; i++) {
                    writew(readw(VGABASE+2*(max_xpos*k+i)),
                           VGABASE + 2*(max_xpos*j + i));
                }
            }
            for (i = 0; i < max_xpos; i++)
                writew(0x720, VGABASE + 2*(max_xpos*j + i));
            current_ypos = max_ypos-1;
        }
        if (c == '\n') {
            current_xpos = 0;
            current_ypos++;
        } else if (c != '\r')  {
            writew(((0x7 << 8) | (unsigned short) c),
                   VGABASE + 2*(max_xpos*current_ypos +
                        current_xpos++));
            if (current_xpos >= max_xpos) {
                current_xpos = 0;
                current_ypos++;
            }
        }
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
