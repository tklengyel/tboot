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

#define TBOOT_LOG_LEVEL_NONE    0x00
#define TBOOT_LOG_LEVEL_ALL     0xFF

#define TBOOT_LOG_TARGET_NONE   0x00
#define TBOOT_LOG_TARGET_VGA    0x01
#define TBOOT_LOG_TARGET_SERIAL 0x02
#define TBOOT_LOG_TARGET_MEMORY 0x04

extern uint8_t g_log_level;
extern uint8_t g_log_targets;
extern uint8_t g_vga_delay;

#define printk       early_printk

extern void early_memlog_init(void);
extern void early_memlog_write(const char *str, unsigned int count);
extern void early_memlog_print(void);

extern void early_serial_parse_port_config(const char *conf);
extern void early_serial_init(void);
extern void early_serial_write(const char *str, unsigned int count);

extern void early_vga_write(const char *str, unsigned int count);

extern void early_printk_init(void);
extern void early_printk(const char *fmt, ...)
                         __attribute__ ((format (printf, 1, 2)));

#endif
