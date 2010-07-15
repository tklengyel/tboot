/*
 * acminfo.c: Linux app that will display header information for a TXT
 *            Authenticated Code Module (ACM)
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
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#define printk   printf
#include "../include/uuid.h"
#include "../include/mle.h"
#include "../tboot/include/misc.h"
#include "../tboot/include/txt/acmod.h"
#include "../tboot/include/txt/config_regs.h"

/* override of fn. that will be called by verify_acmod() */
typedef struct {
    uint32_t acm_max_size;
} getsec_parameters_t;
static bool get_parameters(getsec_parameters_t *params)
{
    params->acm_max_size = 0x8000;
    return true;
}

#define IS_INCLUDED    /* prevent acmod.c #include */
#include "../tboot/txt/acmod.c"

static void *load_acm(const char *file_name, size_t *size)
{
    int fd;
    struct stat sb;
    void *addr;

    fd = open(file_name, O_RDONLY);
    if ( fd == -1 ) {
        printf("Error:  failed to open file %s\n", file_name);
        return NULL;
    }

    if ( fstat(fd, &sb) == -1 ) {
        printf("Error:  failed to get file length\n");
        close(fd);
        return NULL;
    }

    addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( addr == NULL ) {
        printf("Error:  failed to map file %s of size %lu\n", file_name,
               sb.st_size);
        close(fd);
        return NULL;
    }

    if ( size != NULL )
        *size = sb.st_size;

    return addr;
}

static void print_hex(const char* prefix, uint8_t *start, size_t len)
{
    uint8_t *end = start + len;
    while ( start < end ) {
        printf("%s", prefix);
        for ( int i = 0; i < 16; i++ ) {
            if ( start < end )
                printf("%02x ", *start);
            start++;
        }
        printf("\n");
    }
}

static bool display_acm(void *acm_addr, size_t size, const char *file_name)
{
    if ( !is_acmod(acm_addr, size, NULL, false) )
        return false;

    acm_hdr_t *hdr = (acm_hdr_t *)acm_addr;

    print_acm_hdr(hdr, file_name);

    /* display signature info */
    printf("signature information:\n");
    printf("\t key size*4: 0x%x (%u)\n", hdr->key_size, hdr->key_size);
    printf("\t RSA public key:\n");
    print_hex("\t     ", hdr->rsa2048_pubkey, hdr->key_size*4);
    printf("\t RSA public key exponent: 0x%08x\n", hdr->pub_exp);
    printf("\t PKCS #1.5 RSA signature:\n");
    print_hex("\t     ", hdr->rsa2048_sig, 256);

    return true;
}

int main(int argc, char *argv[])
{
    void *acm_mem = NULL;
    char *acm_file;
    size_t size;
    bool valid;

    if ( argc != 2 ) {
        printf("usage:  %s acm_file_name\n", argv[0]);
        return 1;
    }

    acm_file = argv[1];

    /* load ACM file into memory */
    acm_mem = load_acm(acm_file, &size);
    if ( acm_mem == NULL ) {
        printf("Error:  failed to read ACM %s\n", acm_file);
        return 1;
    }

    /* display the ACM info */
    valid = display_acm(acm_mem, size, acm_file);

    /* this allows us to use dump-acm return code to indicate valid ACM */
    return valid ? 0 : 1;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
