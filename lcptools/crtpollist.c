/*
 * crtpollist.c: Intel(R) TXT policy list (LCP_POLICY_LIST) creation tool
 *
 * Copyright (c) 2009-2011, Intel Corporation
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
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "../include/lcp_hlp.h"
#include "polelt_plugin.h"
#include "pollist.h"
#include "polelt.h"
#include "lcputils2.h"

static const char help[] =
    "Usage: lcp_crtpollist <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy list.\n\n"
    "--create\n"
    "        [--ver <version>]        version\n"
    "        --out <FILE>             policy list file\n"
    "        [FILE]...                policy element files\n"
    "--sign\n"
    "        --pub <key file>         PEM file of public key\n"
    "        [--priv <key file>]      PEM file of private key\n"
    "        [--rev <rev ctr>]        revocation counter value\n"
    "        [--nosig]                don't add SigBlock\n"
    "        --out <FILE>             policy list file\n"
    "--addsig\n"
    "        --sig <FILE>             file containing signature (big-endian)\n"
    "        --out <FILE>             policy list file\n"
    "--show\n"
    "        <FILE>                   policy list file\n"
    "--help\n"
    "--verbose                        enable verbose output; can be\n"
    "                                 specified with any command\n\n"
    "The public and private keys can be created as follows:\n"
    "  openssl genrsa -out privkey.pem 2048\n"
    "  openssl rsa -pubout -in privkey.pem -out pubkey.pem\n";

bool verbose = false;

static struct option long_opts[] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},

    {"create",         no_argument,          NULL,     'C'},
    {"sign",           no_argument,          NULL,     'S'},
    {"addsig",         no_argument,          NULL,     'A'},
    {"show",           no_argument,          NULL,     'W'},

    /* options */
    {"ver",            required_argument,    NULL,     'v'},
    {"out",            required_argument,    NULL,     'o'},
    {"pub",            required_argument,    NULL,     'u'},
    {"priv",           required_argument,    NULL,     'i'},
    {"rev",            required_argument,    NULL,     'r'},
    {"nosig",          no_argument,          NULL,     'n'},
    {"sig",            required_argument,    NULL,     's'},

    {"verbose",        no_argument,          (int *)&verbose, true},
    {0, 0, 0, 0}
};

#define MAX_FILES   32

static uint16_t       version = LCP_DEFAULT_POLICY_LIST_VERSION;
static char           pollist_file[MAX_PATH] = "";
static char           pubkey_file[MAX_PATH] = "";
static char           privkey_file[MAX_PATH] = "";
static char           sig_file[MAX_PATH] = "";
static uint16_t       rev_ctr = 0;
static bool           no_sigblock = false;
static unsigned int   nr_files = 0;
static char           files[MAX_FILES][MAX_PATH];


static lcp_signature_t *read_pubkey_file(const char *file)
{
    FILE *fp = fopen(file, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open .pem file %s: %s\n", file,
              strerror(errno));
        return NULL;
    }

    RSA *pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if ( pubkey == NULL ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to read .pem file %s: %s\n", file,
              ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        return NULL;
    }

    unsigned int keysize = RSA_size(pubkey);
    if ( keysize == 0 ) {
        ERROR("Error: public key size is 0\n");
        RSA_free(pubkey);
        return NULL;
    }

    lcp_signature_t *sig = malloc(sizeof(*sig) + 2*keysize);
    if ( sig == NULL ) {
        ERROR("Error: failed to allocate sig\n");
        RSA_free(pubkey);
        return NULL;
    }

    memset(sig, 0, sizeof(*sig) + 2*keysize);
    sig->pubkey_size = keysize;
   
    BIGNUM *modulus = BN_new();
    /* OpenSSL Version 1.1.0 and later don't allow direct access to RSA 
       stuct */ 
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_get0_key(pubkey, (const BIGNUM **)&modulus, NULL, NULL); 
    #else
    	modulus = pubkey->n;
    #endif
    unsigned char key[keysize];
    BN_bn2bin(modulus, key);
    /* openssl key is big-endian and policy requires little-endian, so reverse
       bytes */
    for ( unsigned int i = 0; i < keysize; i++ )
        sig->pubkey_value[i] = *(key + (keysize - i - 1));

    if ( verbose ) {
        LOG("signature:\n");
        display_signature("    ", sig, false);
    }
 
    BN_free(modulus);
    RSA_free(pubkey);
    return sig;
}

static bool sign_list_data(lcp_policy_list_t *pollist, const char *privkey_file)
{
    if ( pollist == NULL || privkey_file == NULL )
        return false;

    lcp_signature_t *sig = get_signature(pollist);
    if ( sig == NULL )
        return false;

    /* read private key */
    FILE *fp = fopen(privkey_file, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open .pem file %s: %s\n", privkey_file,
              strerror(errno));
        return false;
    }

    RSA *privkey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if ( privkey == NULL ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to read .pem file %s: %s\n", privkey_file,
              ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        return false;
    }

    if ( RSA_size(privkey) != sig->pubkey_size ) {
        ERROR("Error: private and public key sizes don't match\n");
        RSA_free(privkey);
        return false;
    }

    /* first create digest of list (all except sig_block) */
    tb_hash_t digest;
    if ( !hash_buffer((const unsigned char *)pollist,
                      get_policy_list_size(pollist) - sig->pubkey_size,
                      &digest, TB_HALG_SHA1_LG) ) {
        ERROR("Error: failed to hash list\n");
        RSA_free(privkey);
        return false;
    }
    if ( verbose ) {
        LOG("digest: ");
        print_hex("", &digest, get_hash_size(TB_HALG_SHA1_LG));
    }

    /* sign digest */
    /* work on buffer because we need to byte swap before putting in policy */
    uint8_t sigblock[sig->pubkey_size];
    unsigned int sig_len = sig->pubkey_size;
    if ( !RSA_sign(NID_sha1, (const unsigned char *)&digest,
                   get_hash_size(TB_HALG_SHA1_LG), sigblock,
                   &sig_len, privkey) ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to sign list: %s\n", 
              ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        RSA_free(privkey);
        return false;
    }
    if ( sig_len != sig->pubkey_size ) {
        ERROR("Error: signature length mismatch\n");
        RSA_free(privkey);
        return false;
    }

    RSA_free(privkey);

    /* sigblock is big-endian and policy needs little-endian, so reverse */
    for ( unsigned int i = 0; i < sig->pubkey_size; i++ )
        *(get_sig_block(pollist) + i) = *(sigblock + (sig->pubkey_size - i - 1));

    if ( verbose ) {
        LOG("signature:\n");
        display_signature("    ", sig, false);
    }

    return true;
}

static int create(void)
{
    lcp_policy_list_t *pollist = create_empty_policy_list();
    if ( pollist == NULL )
        return 1;

    pollist->version = version;

    for ( unsigned int i = 0; i < nr_files; i++ ) {
        size_t len;
        lcp_policy_element_t *elt = read_file(files[i], &len, false);
        if ( elt == NULL ) {
            free(pollist);
            return 1;
        }
        if ( !verify_policy_element(elt, len) ) {
            free(pollist);
            return 1;
        }
        pollist = add_policy_element(pollist, elt);
        if ( pollist == NULL )
            return 1;
    }

    bool write_ok = write_policy_list_file(pollist_file, pollist);

    free(pollist);
    return write_ok ? 0 : 1;
}

static int sign(void)
{
    /* read existing policy list file */
    bool no_sigblock_ok = true;
    lcp_policy_list_t *pollist = read_policy_list_file(pollist_file, false,
                                                       &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    /* read public key file */
    lcp_signature_t *sig = read_pubkey_file(pubkey_file);
    if ( sig == NULL ) {
        free(pollist);
        return 1;
    }
    /* check public key size */
    if ( (sig->pubkey_size != 128 /* 1024 bits */)
         && (sig->pubkey_size != 256 /* 2048 bits */)
         && (sig->pubkey_size != 384 /* 3072 bits */) ) {
        ERROR("Error: public key size is not 1024/2048/3072 bits\n");
        free(sig);
        free(pollist);
        return 1;
    }

    sig->revocation_counter = rev_ctr;
    pollist = add_signature(pollist, sig);
    if ( pollist == NULL ) {
        free(sig);
        return 1;
    }
    pollist->sig_alg = LCP_POLSALG_RSA_PKCS_15;

    if ( no_sigblock )
        memset(get_sig_block(pollist), 0, sig->pubkey_size);
    else {
        if ( !sign_list_data(pollist, privkey_file) ) {
            free(sig);
            free(pollist);
            return 1;
        }
    }

    bool write_ok = write_policy_list_file(pollist_file, pollist);

    free(sig);
    free(pollist);
    return write_ok ? 0 : 1;
}

static int addsig(void)
{
    /* read existing policy list file */
    bool no_sigblock_ok = true;
    lcp_policy_list_t *pollist = read_policy_list_file(pollist_file, false,
                                                       &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    lcp_signature_t *sig = get_signature(pollist);
    if ( sig == NULL ) {
        free(pollist);
        return 1;
    }
    /* check public key size */
    if ( (sig->pubkey_size != 128 /* 1024 bits */)
         && (sig->pubkey_size != 256 /* 2048 bits */)
         && (sig->pubkey_size != 384 /* 3072 bits */) ) {
        ERROR("Error: public key size is not 1024/2048/3072 bits\n");
        free(pollist);
        return 1;
    }

    /* read signature file */
    size_t len;
    uint8_t *data = read_file(sig_file, &len, false);
    if ( data == NULL ) {
        free(pollist);
        return 1;
    }

    if ( len != sig->pubkey_size ) {
        ERROR("Error: signature file size doesn't match public key size\n");
        free(pollist);
        free(data);
        return 1;
    }

    /* verify that this sigblock actually matches the policy list */
    LOG("verifying signature block...\n");
    if ( !verify_signature((const unsigned char *)pollist,
                           get_policy_list_size(pollist) - sig->pubkey_size,
                           sig->pubkey_value, sig->pubkey_size,
                           data, false) ) {
        ERROR("Error: signature file does not match policy list\n");
        free(pollist);
        free(data);
        return 1;
    }
    LOG("signature file verified\n");

    /* data is big-endian and policy needs little-endian, so reverse */
    for ( unsigned int i = 0; i < sig->pubkey_size; i++ )
        *(get_sig_block(pollist) + i) = *(data + (sig->pubkey_size - i - 1));

    if ( verbose ) {
        LOG("signature:\n");
        display_signature("    ", sig, false);
    }

    bool write_ok = write_policy_list_file(pollist_file, pollist);

    free(pollist);
    free(data);
    return write_ok ? 0 : 1;
}

static int show(void)
{
    /* read existing file */
    bool no_sigblock_ok = true;
    lcp_policy_list_t *pollist = read_policy_list_file(files[0], false,
                                                       &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    DISPLAY("policy list file: %s\n", files[0]);
    display_policy_list("", pollist, false);

    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 && !no_sigblock_ok ) {
        if ( verify_pollist_sig(pollist) )
            DISPLAY("signature verified\n");
        else
            DISPLAY("failed to verify signature\n");
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int cmd = 0;
    bool prev_cmd = false;
    int c;

    do {
        c = getopt_long_only(argc, argv, "", long_opts, NULL);

        switch (c) {
            /* commands */
        case 'H':          /* help */
        case 'C':          /* create */
        case 'S':          /* sign */
        case 'A':          /* addsig */
        case 'W':          /* show */
            if ( prev_cmd ) {
                ERROR("Error: only one command can be specified\n");
                return 1;
            }
            prev_cmd = true;
            cmd = c;
            LOG("cmdline opt: command: %c\n", cmd);
            break;

        case 'v':            /* version */
            version = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: ver: 0x%x (%u)\n", version, version);
            break;

        case 'o':            /* out */
            strlcpy(pollist_file, optarg, sizeof(pollist_file));
            LOG("cmdline opt: out: %s\n", pollist_file);
            break;

        case 'u':            /* pub */
            strlcpy(pubkey_file, optarg, sizeof(pubkey_file));
            LOG("cmdline opt: pub: %s\n", pubkey_file);
            break;

        case 'i':            /* priv */
            strlcpy(privkey_file, optarg, sizeof(privkey_file));
            LOG("cmdline opt: pub: %s\n", privkey_file);
            break;

        case 'r':            /* rev */
            rev_ctr = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: rev: 0x%x (%u)\n", rev_ctr, rev_ctr);
            break;

        case 'n':            /* nosig */
            no_sigblock = true;
            LOG("cmdline opt: nosig: %u\n", no_sigblock);
            break;

        case 's':            /* sigblock */
            strlcpy(sig_file, optarg, sizeof(sig_file));
            LOG("cmdline opt: sigblock: %s\n", sig_file);
            break;

        case 0:
        case -1:
            break;

        default:
            ERROR("Error: unrecognized option\n");
            return 1;
        }
    } while ( c != -1 );

    /* process any remaining argv[] items */
    while ( optind < argc && nr_files < ARRAY_SIZE(files) ) {
        LOG("cmdline opt: file: %s\n", argv[optind]);
        strlcpy(files[nr_files++], argv[optind], sizeof(files[0]));
        optind++;
    }

    if ( cmd == 0 ) {
        ERROR("Error: no command option was specified\n");
        return 1;
    }
    else if ( cmd == 'H' ) {        /* --help */
        DISPLAY("%s", help);
        return 0;
    }
    else if ( cmd == 'C' ) {        /* --create */
        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }
        return create();
    }
    else if ( cmd == 'S' ) {        /* --sign */
        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }
        if ( *pubkey_file == '\0' ) {
            ERROR("Error: no public key file specified\n");
            return 1;
        }
        if ( no_sigblock ) {     /* no signature wanted */
            if ( *privkey_file != '\0' ) {
                ERROR("Error: private key file specified with --nosig option\n");
                return 1;
            }
        }
        else {                   /* we generate sig, so need private key */
            if ( *privkey_file == '\0' ) {
                ERROR("Error: no private key file specified\n");
                return 1;
            }
        }
        return sign();
    }
    else if ( cmd == 'A' ) {        /* --addsig */
        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }
        if ( *sig_file == '\0' ) {
            ERROR("Error: no signature file specified\n");
            return 1;
        }
        return addsig();
    }
    else if ( cmd == 'W' ) {        /* --show */
        if ( nr_files != 1 ) {
            ERROR("Error: no policy list file specified\n");
            return 1;
        }
        return show();
    }

    ERROR("Error: unknown command\n");
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
