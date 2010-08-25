/*
 * vga.c:  fns for outputting strings to VGA display
 *
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <types.h>
#include <stdbool.h>
#include <string.h>
#include <misc.h>
#include <io.h>
#include <vga.h>

static uint16_t * const screen = (uint16_t * const)VGA_BASE;
static __data uint8_t cursor_x, cursor_y;
static __data unsigned int num_lines;
uint8_t g_vga_delay = 0;       /* default to no delay */

static inline void reset_screen(void)
{
    memset(screen, 0, SCREEN_BUFFER);
    cursor_x = 0;
    cursor_y = 0;
    num_lines = 0;

    outb(CTL_ADDR_REG, START_ADD_HIGH_REG);
    outb(CTL_DATA_REG, 0x00);
    outb(CTL_ADDR_REG, START_ADD_LOW_REG);
    outb(CTL_DATA_REG, 0x00);
}

static void scroll_screen(void)
{
    for ( int y = 1; y < MAX_LINES; y++ ) {
        for ( int x = 0; x < MAX_COLS; x++ )
            writew(VGA_ADDR(x, y-1), readw(VGA_ADDR(x, y)));
    }
    /* clear last line */
    for ( int x = 0; x < MAX_COLS; x++ )
        writew(VGA_ADDR(x, MAX_LINES-1), 0x720);
}

static void __putc(uint8_t x, uint8_t y, int c)
{
    screen[(y * MAX_COLS) + x] = (COLOR << 8) | c;
}

static void vga_putc(int c)
{
    bool new_row = false;

    switch ( c ) {
        case '\n':
            cursor_y++;
            cursor_x = 0;
            new_row = true;
            break;
        case '\r':
            cursor_x = 0;
            break;
        case '\t':
            cursor_x += 4;
            break;
        default:
            __putc(cursor_x, cursor_y, c);
            cursor_x++;
            break;
    }

    if ( cursor_x >= MAX_COLS ) {
        cursor_x %= MAX_COLS;
        cursor_y++;
        new_row = true;
    }

    if ( new_row ) {
        num_lines++;
        if ( cursor_y >= MAX_LINES ) {
            scroll_screen();
            cursor_y--;
        }

        /* (optionally) pause after every screenful */
        if ( (num_lines % (MAX_LINES - 1)) == 0 && g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
    }
}

void vga_init(void)
{
    reset_screen();
}

void vga_puts(const char *s, unsigned int cnt)
{
    while ( *s && cnt-- ) {
        vga_putc(*s);
        s++;
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
