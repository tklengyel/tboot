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
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <io.h>
#include <cmdline.h>
#include <printk.h>

#define VGA_BASE                    0xb8000

/* 80*25 text mode */
#define MAX_LINES                   25
#define MAX_COLS                    80
#define SCREEN_BUFFER               (MAX_LINES*MAX_COLS*2)
#define VGA_ADDR(x, y)              (VGA_BASE + 2*(MAX_COLS*(y) + (x)))

/* registers */
#define CTL_ADDR_REG                0x3D4                             
#define CTL_DATA_REG                0x3D5
#define START_ADD_HIGH_REG          0x0C
#define START_ADD_LOW_REG           0x0D 

/* colors */
#define COLOR_BLACK                 0x00
#define COLOR_BLUE                  0x01
#define COLOR_GREEN                 0x02
#define COLOR_CYAN                  0x03
#define COLOR_RED                   0x04
#define COLOR_MAGENTA               0x05
#define COLOR_BROWN                 0x06
#define COLOR_LTGRAY                0x07
#define COLOR_DKGRAY                0x08
#define COLOR_LTBLUE                0x09
#define COLOR_LTGREEN               0x0A
#define COLOR_LTCYAN                0x0B
#define COLOR_LTRED                 0x0C
#define COLOR_LTMAGENTA             0x0D
#define COLOR_LTBROWN               0x0E
#define COLOR_WHITE                 0x0F

#define COLOR                       ((COLOR_BLACK << 4) | COLOR_LTGRAY)

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

    if ( new_row && cursor_y >= MAX_LINES ) {
        scroll_screen();
        num_lines++;
        cursor_y--;

        /* (optionally) pause after every screenful */
        if ( (num_lines % (MAX_LINES - 1)) == 0 && g_vga_delay > 0 )
            delay(g_vga_delay);
    }
}

void vga_init(void)
{
    reset_screen();
    get_tboot_vga_delay();
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
