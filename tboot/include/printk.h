/*
 * printk.h: printk to serial for very early boot stages
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

#ifndef __PRINTK_H__
#define __PRINTK_H__

#define printk       early_serial_printk

extern void init_log(void);
extern void print_log(void);
extern void early_serial_printk(const char *fmt, ...)
                         __attribute__ ((format (printf, 1, 2)));
extern void early_serial_init(void);
extern void early_vga_printk(const char *str);

#endif
