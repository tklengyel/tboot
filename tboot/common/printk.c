/*
 * printk.c:  printk() output fn and helpers
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <mutex.h>
#include <misc.h>
#include <printk.h>
#include <cmdline.h>
#include <tboot.h>
#include <lz.h>

uint8_t g_log_level = TBOOT_LOG_LEVEL_ALL;
uint8_t g_log_targets = TBOOT_LOG_TARGET_SERIAL | TBOOT_LOG_TARGET_VGA;

static struct mutex print_lock;

/*
 * memory logging
 */

/* memory-based serial log (ensure in .data section so that not cleared) */
__data tboot_log_t *g_log = NULL;

static void memlog_init(void)
{


   if ( g_log == NULL ) {
       g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
       g_log->uuid = (uuid_t)TBOOT_LOG_UUID;
       g_log->curr_pos = 0;
       g_log->zip_count = 0;
       for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
       for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
       }

    /* initialize these post-launch as well, since bad/malicious values */
    /* could compromise environment */
    g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
    g_log->max_size = TBOOT_SERIAL_LOG_SIZE - sizeof(*g_log);

    /* if we're calling this post-launch, verify that curr_pos is valid */
    if ( g_log->zip_pos[g_log->zip_count] > g_log->max_size ){
        g_log->curr_pos = 0;
        g_log->zip_count = 0;
        for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
        for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
    }
    if ( g_log->curr_pos > g_log->max_size )
        g_log->curr_pos = g_log->zip_pos[g_log->zip_count];
}

static void memlog_write( const char *str, unsigned int count)
{
    /* allocate a 32K temp buffer for compressed log  */
    static char buf[32*1024];
    char *out=buf;
    int zip_size;
    uint32_t zip_pos;
    bool log_reset_flag;

    if ( g_log == NULL || count > g_log->max_size )
        return;

    /* Check if there is space for the new string and a null terminator  */
    if (g_log->curr_pos + count + 1> g_log->max_size) {

        /* If there are space issues, only then log will be reset */
        log_reset_flag = false;

        /* Check if there is space to add another compressed chunk */
        if(g_log->zip_count >= ZIP_COUNT_MAX)
            log_reset_flag = true;
        else{
            /* Get the start position of the new compressed chunk */
            zip_pos = g_log->zip_pos[g_log->zip_count];

            /*  Compress the last part of the log buffer that is not compressed,
                and put the compressed output in out (buf) */
            zip_size = LZ_Compress(&g_log->buf[zip_pos], out, (g_log->curr_pos - zip_pos), sizeof(buf) );

            /* Check if buf was large enough for LZ_compress to succeed */
            if( zip_size < 0 )
                log_reset_flag = true;
            else{
                /*  Check if there is space to add the compressed string, the
                    new string and a null terminator to the log */
                if( (zip_pos + zip_size + count + 1) > g_log->max_size )
                    log_reset_flag = true;
                else{
                    /*  Add the new compressed chunk to the log buffer,
                        over-writing the last part of the log that was just
                        compressed */
                    memcpy(&g_log->buf[zip_pos], out, zip_size);
                    g_log->zip_size[g_log->zip_count] = zip_size;
                    g_log->zip_count++;
                    g_log->curr_pos = zip_pos + zip_size;

                    /*  Set a NULL ending */
                    g_log->buf[g_log->curr_pos] ='\0';

                    /*  Only if there is space to add another compressed chunk,
                        prepare its start position. */
                    if( g_log->zip_count < ZIP_COUNT_MAX )
                        g_log->zip_pos[g_log->zip_count] = g_log->curr_pos;
                }
            }
        }

        /* There was some space-shortage problem. Reset the log. */
        if ( log_reset_flag ){
            g_log->curr_pos = 0;
            for( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
            for( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
            g_log->zip_count = 0;
        }
    }

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

void printk_init(void)
{
    mtx_init(&print_lock);

    /* parse loglvl from string to int */
    get_tboot_loglvl();

    /* parse logging targets */
    get_tboot_log_targets();

    /* parse serial settings */
    if ( !get_tboot_serial() )
        g_log_targets &= ~TBOOT_LOG_TARGET_SERIAL;

    if ( g_log_targets & TBOOT_LOG_TARGET_MEMORY )
        memlog_init();
    if ( g_log_targets & TBOOT_LOG_TARGET_SERIAL )
        serial_init();
    if ( g_log_targets & TBOOT_LOG_TARGET_VGA ) {
        vga_init();
        get_tboot_vga_delay(); /* parse vga delay time */
    }
}

#define WRITE_LOGS(s, n) \
    do {                                                                 \
        if (g_log_targets & TBOOT_LOG_TARGET_MEMORY) memlog_write(s, n); \
        if (g_log_targets & TBOOT_LOG_TARGET_SERIAL) serial_write(s, n); \
        if (g_log_targets & TBOOT_LOG_TARGET_VGA) vga_write(s, n);       \
    } while (0)

void printk(const char *fmt, ...)
{
    char buf[256];
    char *pbuf = buf;
    int n;
    va_list ap;
    uint8_t log_level;
    static bool last_line_cr = true;

    memset(buf, '\0', sizeof(buf));
    va_start(ap, fmt);
    n = vscnprintf(buf, sizeof(buf), fmt, ap);

    log_level = get_loglvl_prefix(&pbuf, &n);

    if ( !(g_log_level & log_level) )
        goto exit;

    mtx_enter(&print_lock);
    /* prepend "TBOOT: " if the last line that was printed ended with a '\n' */
    if ( last_line_cr )
        WRITE_LOGS("TBOOT: ", 8);

    last_line_cr = (n > 0 && (*(pbuf+n-1) == '\n'));
    WRITE_LOGS(pbuf, n);
    mtx_leave(&print_lock);

exit:
    va_end(ap);
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
