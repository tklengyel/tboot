/*
 * printk.h: printk to serial for very early boot stages
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#ifndef __PRINTK_H__
#define __PRINTK_H__

#include <com.h>
#include <vga.h>

#define TBOOT_LOG_LEVEL_NONE    0x00
#define TBOOT_LOG_LEVEL_ALL     0xFF

#define TBOOT_LOG_TARGET_NONE   0x00
#define TBOOT_LOG_TARGET_VGA    0x01
#define TBOOT_LOG_TARGET_SERIAL 0x02
#define TBOOT_LOG_TARGET_MEMORY 0x04

extern uint8_t g_log_level;
extern uint8_t g_log_targets;
extern uint8_t g_vga_delay;
extern serial_port_t g_com_port;

#define serial_init()         comc_init()
#define serial_write(s, n)    comc_puts(s, n)

#define vga_write(s,n)        vga_puts(s, n)

extern void printk_init(void);
extern void printk(const char *fmt, ...)
                         __attribute__ ((format (printf, 1, 2)));

#endif
