/*
 * mhash.c: tool to determine the SHA-1 hash of a Intel(R) TXT MLE
 *
 * Copyright (c) 2006-2008, Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <getopt.h>
#include <zlib.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#define PRINT   printf
#include "../include/elf_defns.h"
#include "../include/uuid.h"
#include "../include/mle.h"

#define SHA1_LENGTH    20

static bool verbose = false;

#define log_info(fmt, ...)     verbose ? printf(fmt, ##__VA_ARGS__) : 0


/*
 * is_elf_image
 *
 * check an image is elf or not?
 *
 */
static bool is_elf_image(const void *image, const size_t size)
{
    elf_header_t *elf;

    log_info("checking whether image is an elf image ... ");
    if ( image == NULL ) {
        log_info(": failed! - Pointer is zero.\n");
        return false;
    }

    /* check size */
    if ( sizeof(elf_header_t) > size ) {
        log_info(": failed! - Image size is smaller than ELF header size.\n");
        return false;
    }

    elf = (elf_header_t *)image;

    /* check magic number for ELF */
    if (( elf->e_ident[EI_MAG0] != ELFMAG0 )
     || ( elf->e_ident[EI_MAG1] != ELFMAG1 )
     || ( elf->e_ident[EI_MAG2] != ELFMAG2 )
     || ( elf->e_ident[EI_MAG3] != ELFMAG3 )) {
        log_info(": failed! - ELF magic number is not matched.\n");
        return false;
    }

    /* check data encoding in ELF */
    if ( elf->e_ident[EI_DATA] != ELFDATA2LSB ) {
        log_info(": failed! - ELF data encoding is not the least significant "
               "byte occupying the lowest address.\n");
        return false;
    }

    /* check ELF image is executable? */
    if ( elf->e_type != ET_EXEC ) {
        log_info(": failed! - ELF image is not executable.\n");
        return false;
    }

    /* check ELF image is for IA? */
    if ( elf->e_machine != EM_386 ) {
        log_info(": failed! - ELF image is not for IA.\n");
        return false;
    }

    /* check ELF version is valid? */
    if ( elf->e_version != EV_CURRENT ) {
        log_info(": failed! - ELF version is invalid.\n");
        return false;
    }

    if ( sizeof(elf_program_header_t) > elf->e_phentsize ) {
        log_info(": failed! - Program size is smaller than program "
               "header size.\n");
        return false;
    }

    log_info(": succeeded!\n");
    return true;
}

static bool get_elf_image_range(const elf_header_t *elf, void **start,
                                void **end)
{
    int i;
    unsigned long u_start, u_end;

    if (elf == NULL) {
        log_info("Error: ELF header pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    if ((start == NULL) || (end == NULL)) {
        log_info("Error: Output pointers are zero.\n");
        return false;
    }

    u_start = 0;
    u_end = 0;
    for (i = 0; i < elf->e_phnum; i++) {
        elf_program_header_t *ph = (elf_program_header_t *)
                         ((void *)elf + elf->e_phoff + i*elf->e_phentsize);
        if (ph->p_type == PT_LOAD) {
            if (u_start > ph->p_paddr)
                u_start = ph->p_paddr;
            if (u_end < ph->p_paddr+ph->p_memsz)
                u_end = ph->p_paddr+ph->p_memsz;
        }
    }

    if (u_start >= u_end) {
        *start = NULL;
        *end = NULL;
        return false;
    }
    else {
        *start = (void *)u_start;
        *end = (void *)u_end;
        return true;
    }
}

/*
 *
 * expand entire file into memory
 *
 */
static bool expand_elf_image(const elf_header_t *elf, void *base, size_t size)
{
    int i;

    log_info("expanding elf image ... ");
    if ( elf == NULL ) {
        log_info(": failed! - ELF header pointer is zero.\n");
        return false;
    }

    /* assumed that already passed is_elf_image() check */

    /* load elf image into memory */
    for (i = 0; i < elf->e_phnum; i++) {
        elf_program_header_t *ph = (elf_program_header_t *)
                         ((void *)elf + elf->e_phoff + i*elf->e_phentsize);

        if (ph->p_type == PT_LOAD) {
            if ( ph->p_memsz > size ) {
                log_info("expanded image exceeded allocated size\n");
                return false;
            }
            memcpy(base, (void *)elf + ph->p_offset, ph->p_filesz);
            memset(base + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);
            base += ph->p_memsz;
            size -= ph->p_memsz;
        }
    }

    log_info(": succeeded!.\n");
    return true;
}

/*
 * print_dump
 *
 * dump the memory
 *
 */
#if 0
static void print_dump(uint32_t s, uint32_t e)
{
    uint32_t i,j;
    unsigned char* p;
    for ( i = s, j = 0; i < e; i++, j++ ) {
        p = (unsigned char*)i;
        log_info("%02x ", *p);
        if ( j % 20 == 0 )
            log_info("\n");
    }
    log_info("\n");
}
#endif

/*
 * read_file
 *
 * read file from disk, if compressed, uncompress it
 *
 */
static bool read_file(const char *filename, void **buffer, size_t *length)
{
    gzFile fcompressed = NULL;
    FILE *fdecompressed = NULL;
    struct stat filestat;
    char tmpbuffer[1024];
    unsigned long i;

    *length = 0;
    *buffer = NULL;

    /* check the file exists or not */
    log_info("checking whether the file exists or not ... ");
    if ( stat(filename, &filestat) )
        goto error;
    log_info(": existed!\n");

    /* try uncompress the file (gzopen will handle uncompressed files too) */
    log_info("trying to uncompress the file ... ");
    fcompressed = gzopen(filename, "rb");
    if ( !fcompressed ) {
        log_info(": failed!\n");
        return false;
    }
    log_info(": succeeded!\n");

    log_info("creating a temporary file to uncompress ... ");
    fdecompressed = tmpfile();
    if ( !fdecompressed )
        goto error;
    log_info(": succeeded!\n");

    log_info("opening the decompressed file ... ");
    while ( !gzeof(fcompressed) ) {
        i = gzread(fcompressed, tmpbuffer, 1024);
        *length += i;
        if ( fwrite(tmpbuffer, 1, i, fdecompressed) != i )
            goto error;
    }
    log_info(": succeeded!\n");
    gzclose(fcompressed);
    fcompressed = NULL;

    log_info("testing decompression is ... ");
    if ( *length > 0 ) {
        log_info(": succeeded!\n");
        /* uncompression succeeded */
        fseek(fdecompressed, 0, SEEK_SET);
    }
    else {
        log_info(": failed!\n");
        goto error;
    }

    /* read file into buffer */
    log_info("reading the decompressed file ... ");
    *buffer = malloc(*length);
    if ( *buffer == NULL )
       goto error;
    memset(*buffer, 0, *length);
    if ( fread(*buffer, 1, *length, fdecompressed) != *length )
       goto error;
    fclose(fdecompressed);
    log_info(": succeeded!\n");
    return true;

error:
    log_info(": failed!\n");
    if ( fcompressed )
        gzclose(fcompressed);
    if ( fdecompressed )
        fclose(fdecompressed);
    free(*buffer);
    return false;
}

static mle_hdr_t *find_mle_hdr(void *start, size_t size)
{
    void *end;

    end = start + size - sizeof(uuid_t);
    while ( start <= end ) {
        if ( are_uuids_equal((const uuid_t *)start, &((uuid_t)MLE_HDR_UUID)) )
            return (mle_hdr_t *)start;
        start += sizeof(uuid_t);
    }
    return NULL;
}

/*
 * main
 */
int main(int argc, char* argv[])
{
    void *elf_start=NULL, *elf_end=NULL;
    void *exp_start=NULL;
    void *base=NULL;
    size_t size, exp_size;
    elf_header_t *base_as_elf;
    uint8_t hash[SHA1_LENGTH];
    mle_hdr_t *mle_hdr;
    int i, c;
    bool help = false;
    char *mle_file;
    extern int optind;    /* current index of get_opt() */
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    const EVP_MD *md;
    char *cmdline = NULL;

    while ((c = getopt(argc, (char ** const)argv, "hvc:")) != -1) {
        switch (c) {
            case 'h':
                help = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'c':
                if ( optarg == NULL ) {
                    printf("Misssing command line string for -c option\n");
                    return 1;
                }
                cmdline = malloc(strlen(optarg) + 1);
                if ( cmdline == NULL ) {
                    printf("Out of memory\n");
                    return 1;
                }
                strcpy(cmdline, optarg);
                break;
            default:
                printf("Unknonw command line option\n");
                break;
        }
    }
    if ( help || (optind == argc) ) {
        printf("mhash [-h] [-v] [-c cmdline] mle_file\n"
               "\t-h Help: will print out this help message.\n"
               "\t-v Verbose: display progress indications.\n"
               "\t-c cmdline Command line: specify quote-delimited command line.\n"
               "\tmle_file: file name of MLE binary (gzip or not) to hash.\n");
        free(cmdline);
        return 1;
    }
    mle_file = argv[optind];

    /* read file */
    if ( !read_file(mle_file, &base, &size) )
        goto error;

    /* expand image */
    if ( !is_elf_image(base, size) )
        goto error;
    base_as_elf = (elf_header_t *)base;

    /* get expanded size and allocate memory for it */
    if ( !get_elf_image_range(base_as_elf, &elf_start, &elf_end) )
        goto error;
    exp_size = elf_end - elf_start;
    exp_start = malloc(exp_size);
    if ( exp_start == NULL ) {
        log_info("not enough memory for expanded image\n");
        goto error;
    }

    /* expand the image */
    if ( !expand_elf_image(base_as_elf, exp_start, exp_size) )
        goto error;

    /* find the MLE header in the expanded image */
    mle_hdr = find_mle_hdr(exp_start, exp_size);
    if ( mle_hdr == NULL ) {
        log_info("no MLE header found in image\n");
        goto error;
    }

    /* before hashing, find command line area in MLE then zero-fill and copy
       command line param to it */
    if ( mle_hdr->cmdline_end_off > mle_hdr->cmdline_start_off &&
         cmdline != NULL ) {
        memset(exp_start + mle_hdr->cmdline_start_off, '\0',
               mle_hdr->cmdline_end_off - mle_hdr->cmdline_start_off);
        strncpy(exp_start + mle_hdr->cmdline_start_off, cmdline,
                mle_hdr->cmdline_end_off - mle_hdr->cmdline_start_off - 1);
    }

    /* SHA-1 the MLE portion of the image */
    md = EVP_sha1();
    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, exp_start + mle_hdr->mle_start_off,
                     mle_hdr->mle_end_off - mle_hdr->mle_start_off);
    EVP_DigestFinal(ctx, (unsigned char *)hash, NULL);
    log_info("SHA-1 = ");

    /* we always print the hash regardless of verbose mode */
    for ( i = 0; i < SHA1_LENGTH; i++ ) {
        printf("%02x", hash[i]);
        if ( i < SHA1_LENGTH - 1 )
            printf(" ");
    }
    printf("\n");

    EVP_MD_CTX_destroy(ctx);
    free(base);
    free(exp_start);
    return 0;

error:
    EVP_MD_CTX_destroy(ctx);
    free(base);
    free(exp_start);
    return 1;
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
