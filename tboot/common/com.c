/*-
 * Copyright (c) 1998 Michael Smith (msmith@freebsd.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

/*
 * sys/boot/i386/libi386/comconsole.c
 */

#include <types.h>
#include <stdbool.h>
#include <misc.h>
#include <printk.h>
#include <io.h>
#include <com.h>
#include <cmdline.h>

/* default serial port config */
#define DEFAULT_COMPORT     COM1_ADD
#define DEFAULT_COMSPEED	115200
#define COMC_FMT	        0x3		/* 8N1 */

#define COMC_TXWAIT	    0x40000			/* transmit timeout */
#define COMC_BPS(x)	    (115200 / (x))	/* speed to DLAB divisor */
#define COMC_DIV2BPS(x)	(115200 / (x))	/* DLAB divisor to speed */

#define OUTB(add, val)   outb(g_com_port.comc_port + (add), (val))
#define INB(add)         inb(g_com_port.comc_port + (add))

serial_port_t g_com_port = { DEFAULT_COMPORT, DEFAULT_COMSPEED, COMC_FMT };

static void comc_putchar(int c)
{
    int wait;

    for ( wait = COMC_TXWAIT; wait > 0; wait-- )
        if ( INB(com_lsr) & LSR_TXRDY ) {
            OUTB(com_data, (u_char)c);
            break;
        }
}

static void comc_setup(int speed)
{
    OUTB(com_cfcr, CFCR_DLAB | g_com_port.comc_fmt);
    OUTB(com_dlbl, COMC_BPS(speed) & 0xff);
    OUTB(com_dlbh, COMC_BPS(speed) >> 8);
    OUTB(com_cfcr, g_com_port.comc_fmt);
    OUTB(com_mcr, MCR_RTS | MCR_DTR);

    do
        INB(com_data);
    while ( INB(com_lsr) & LSR_RXRDY );
}

void comc_init(void)
{
    comc_setup(g_com_port.comc_curspeed);
}

void comc_puts(const char *s, unsigned int cnt)
{
    while ( *s && cnt-- ) {
        if ( *s == '\n' )
            comc_putchar('\r');
        comc_putchar(*s++);
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
