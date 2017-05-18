/*
 * crtpollist.c: Intel(R) TXT policy list (LCP_POLICY_LIST) creation tool
 *
 * Copyright (c) 2014, Intel Corporation
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
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "pollist2.h"
#include "polelt.h"
#include "lcputils.h"
#include "pollist1.h"

static const char help[] =
    "Usage: lcp_crtpollist <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy list.\n\n"
    "--create\n"
    "        --out <FILE>             policy list file\n"
    "        [FILE]...                policy element files\n"
    "--sign\n"
    "        --sigalg <rsa|ecdsa|sm2> signature algorithm\n"
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
    {"out",            required_argument,    NULL,     'o'},
    {"sigalg",         required_argument,    NULL,     'a'},
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
static char           sigalg_name[32] = "";
static uint16_t       sigalg_type = TPM_ALG_RSASSA;  
static char           pubkey_file[MAX_PATH] = "";
static char           privkey_file[MAX_PATH] = "";
static char           sig_file[MAX_PATH] = "";
static uint16_t       rev_ctr = 0;
static bool           no_sigblock = false;
static unsigned int   nr_files = 0;
static char           files[MAX_FILES][MAX_PATH];

static lcp_signature_t2 *read_rsa_pubkey_file(const char *file)
{
    LOG("read_rsa_pubkey_file\n");
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

    lcp_signature_t2 *sig = malloc(sizeof(lcp_rsa_signature_t) + 2*keysize);
    if ( sig == NULL ) {
        ERROR("Error: failed to allocate sig\n");
        RSA_free(pubkey);
        return NULL;
    }

    memset(sig, 0, sizeof(lcp_rsa_signature_t) + 2*keysize);
    sig->rsa_signature.pubkey_size = keysize;
   
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
        sig->rsa_signature.pubkey_value[i] = *(key + (keysize - i - 1));

    if ( verbose ) {
        LOG("read_rsa_pubkey_file: signature:\n");
        display_tpm20_signature("    ", sig, TPM_ALG_RSASSA, false);
    }

    LOG("read rsa pubkey succeed!\n");
    BN_free(modulus);
    RSA_free(pubkey);
    return sig;
}

static lcp_signature_t2 *read_ecdsa_pubkey(const EC_POINT *pubkey, const EC_GROUP *ecgroup)
{
    LOG("[read_ecdsa_pubkey]\n");

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_get_affine_coordinates_GFp((const EC_GROUP*)ecgroup, 
            (const EC_POINT *)pubkey, x, y, ctx);
    unsigned int keysize = BN_num_bytes(x) + BN_num_bytes(y);
    lcp_signature_t2 *sig = malloc(sizeof(lcp_ecc_signature_t) + 2*keysize);
    if ( sig == NULL) {
        ERROR("Error: failed to allocate sig\n");
        return NULL;
    }

    memset(sig, 0, sizeof(lcp_ecc_signature_t) + 2*keysize);
    sig->ecc_signature.pubkey_size = keysize;
    unsigned int BN_X_size = BN_num_bytes(x);
    unsigned int BN_Y_size = BN_num_bytes(y); 
    unsigned char key_X[BN_X_size];
    unsigned char key_Y[BN_Y_size];
    BN_bn2bin(x,key_X);
    BN_bn2bin(y,key_Y);
    for ( unsigned int i = 0; i < BN_X_size; i++ ) {
        sig->ecc_signature.qx[i] = *(key_X + (BN_X_size -i - 1));
    }

    for ( unsigned int i = 0; i < BN_Y_size; i++ ) {
        *(sig->ecc_signature.qx + BN_X_size + i) = *(key_Y + (BN_Y_size -i - 1));
    }

    if ( verbose ) {
        LOG("read_ecdsa_pubkey_file: signature:\n");
        display_tpm20_signature("    ", sig, TPM_ALG_ECDSA, false);
    }

    LOG("read ecdsa pubkey succeed!\n");
    return sig;
}

static bool rsa_sign_list_data(lcp_policy_list_t2 *pollist, const char *privkey_file)
{
    LOG("rsa_sign_list_data\n");
    if ( pollist == NULL || privkey_file == NULL )
        return false;

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig == NULL )
        return false;

    if ( pollist->sig_alg == TPM_ALG_RSASSA) {
        LOG("sign_tpm20_list_data: sig_alg == TPM_ALG_RSASSA\n");
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

        if ( RSA_size(privkey) != sig->rsa_signature.pubkey_size ) {
            ERROR("Error: private and public key sizes don't match\n");
            RSA_free(privkey);
            return false;
        }
        uint16_t    hashalg = TPM_ALG_SHA1;
        lcp_mle_element_t2 *mle;
        const lcp_policy_element_t *elt = pollist->policy_elements;
        uint32_t    type = elt->type;
        switch(type){
            case LCP_POLELT_TYPE_MLE2 :
                mle = (lcp_mle_element_t2 *)elt->data;
                hashalg = mle->hash_alg;
                LOG("mle hashalg= 0x%x\n", hashalg);
                break;
            default:
                LOG("unknown element type\n");
        }

        /* first create digest of list (all except sig_block) */
        tb_hash_t digest;
        if ( !hash_buffer((const unsigned char *)pollist,
                    get_tpm20_policy_list_size(pollist) - sig->rsa_signature.pubkey_size,
                    &digest, hashalg) ) {
            ERROR("Error: failed to hash list\n");
            RSA_free(privkey);
            return false;
        }
        if ( verbose ) {
            LOG("digest: ");
            print_hex("", &digest, get_hash_size(hashalg));
        }

        /* sign digest */
        /* work on buffer because we need to byte swap before putting in policy */
        uint8_t sigblock[sig->rsa_signature.pubkey_size];
        unsigned int sig_len = sig->rsa_signature.pubkey_size;

        int result = 0;
        switch(hashalg){
            case TPM_ALG_SHA1:
                result = RSA_sign(NID_sha1, (const unsigned char *)&digest,
                        get_hash_size(hashalg), sigblock,
                        &sig_len, privkey);
                break; 
            case TPM_ALG_SHA256:
                result = RSA_sign(NID_sha256, (const unsigned char *)&digest,
                        get_hash_size(hashalg), sigblock,
                        &sig_len, privkey);
                break; 
            case TPM_ALG_SHA384:
                result = RSA_sign(NID_sha384, (const unsigned char *)&digest,
                        get_hash_size(hashalg), sigblock,
                        &sig_len, privkey);
                break; 
            case TPM_ALG_SHA512:
                result = RSA_sign(NID_sha512, (const unsigned char *)&digest,
                        get_hash_size(hashalg), sigblock,
                        &sig_len, privkey);
                break; 
            default:
                break;
        } 
        if ( !result ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to sign list: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
            RSA_free(privkey);
            return false;
        }
        if ( sig_len != sig->rsa_signature.pubkey_size ) {
            ERROR("Error: signature length mismatch\n");
            RSA_free(privkey);
            return false;
        }

        RSA_free(privkey);

        /* sigblock is big-endian and policy needs little-endian, so reverse */
        for ( unsigned int i = 0; i < sig->rsa_signature.pubkey_size; i++ )
            *(get_tpm20_sig_block(pollist) + i) = *(sigblock + (sig->rsa_signature.pubkey_size - i - 1));

        if ( verbose ) {
            LOG("signature:\n");
            display_tpm20_signature("    ", sig, pollist->sig_alg, false);
        }

        return true;
    }
    return false;
}

static bool ecdsa_sign_tpm20_list_data(lcp_policy_list_t2 *pollist, EC_KEY *eckey)
{
    LOG("[ecdsa_sign_tpm20_list_data]\n");
    if ( pollist == NULL || eckey == NULL )
        return false;

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig == NULL )
        return false;

    if (pollist->sig_alg == TPM_ALG_ECDSA) {
        LOG("ecdsa_sign_tpm20_list_data: sig_alg == TPM_ALG_ECDSA\n");
        /* first create digest of list (all except sig_block) */
        tb_hash_t digest;
        if ( !hash_buffer((const unsigned char *)pollist,
                    get_tpm20_policy_list_size(pollist) - sig->ecc_signature.pubkey_size,
                    &digest, TB_HALG_SHA256) ) {
            ERROR("Error: failed to hash list\n");
            //   RSA_free(privkey);
            return false;
        }
        if ( verbose ) {
            LOG("digest: ");
            print_hex("", &digest, get_hash_size(TB_HALG_SHA1));
        }

        /* sign digest */
        /* work on buffer because we need to byte swap before putting in policy */
        ECDSA_SIG *ecdsasig;
        ecdsasig = ECDSA_do_sign((const unsigned char *)&digest, get_hash_size(TB_HALG_SHA256),eckey );
        if ( ecdsasig == NULL) {
            ERROR("Error: ECDSA_do_sign error\n");
            return false;
        }

        BIGNUM *r = BN_new();
        BIGNUM *s = BN_new();
        
	/* OpenSSL Version 1.1.0 and later don't allow direct access to 
	   ECDSA_SIG stuct */ 
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
      	    ECDSA_SIG_get0(ecdsasig, (const BIGNUM **)&r, (const BIGNUM **)&s);
        #else
    	    r = ecdsasig->r;
    	    s = ecdsasig->s;
        #endif
	unsigned int BN_r_size = BN_num_bytes(r);
        unsigned int BN_s_size = BN_num_bytes(s); 
        unsigned char key_r[BN_r_size];
        unsigned char key_s[BN_s_size];
        BN_bn2bin(r,key_r);
        BN_bn2bin(s,key_s);
        for ( unsigned int i = 0; i < BN_r_size; i++ ) {
            *(get_tpm20_sig_block(pollist) + i) = *(key_r + (BN_r_size -i - 1));
        }

        for ( unsigned int i = 0; i < BN_s_size; i++ ) {
            *(get_tpm20_sig_block(pollist) + BN_r_size + i) = *(key_s + (BN_s_size -i - 1));
        }

        if ( verbose ) {
            display_tpm20_signature("    ", sig, pollist->sig_alg, false);
        }

	BN_free(r);
	BN_free(s);
        return true;
    }
    return false;
}

static int create(void)
{
    LOG("[create]\n");
    if ( version != LCP_TPM20_POLICY_LIST_VERSION )
        return 1;

    LOG("create:version=0x0200\n");
    lcp_policy_list_t2 *pollist = create_empty_tpm20_policy_list();
    if ( pollist == NULL )
        return 1;

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
        pollist = add_tpm20_policy_element(pollist, elt);
        if ( pollist == NULL )
            return 1;
    }
    bool write_ok = write_tpm20_policy_list_file(pollist_file, pollist);

    free(pollist);
    return write_ok ? 0 : 1;
}

static int sign(void)
{
    LOG("[sign]\n");

    /* read existing policy list file */
    bool no_sigblock_ok = true;
    lcp_list_t *pollist = read_policy_list_file(pollist_file, false,
            &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    uint16_t  version ;
    memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
    if ( version != LCP_TPM20_POLICY_LIST_VERSION )
        return 1;

    pollist->tpm20_policy_list.sig_alg = sigalg_type;
    LOG("sign: version==0x0200,sig_alg=0x%x\n",pollist->tpm20_policy_list.sig_alg);
    if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_RSASSA ) {
        /* read public key file */
        lcp_signature_t2 *sig = read_rsa_pubkey_file(pubkey_file);
        if ( sig == NULL ) {
            ERROR("Error: sign: version == 0x0200, sig == NULL\n");
            free(pollist);
            return 1;
        }
        /* check public key size */
        if ( (sig->rsa_signature.pubkey_size != 128 /* 1024 bits */)
                && (sig->rsa_signature.pubkey_size != 256 /* 2048 bits */)
                && (sig->rsa_signature.pubkey_size != 384 /* 3072 bits */) ) {
            ERROR("Error: public key size is not 1024/2048/3072 bits\n");
            free(sig);
            free(pollist);
            return 1;
        }

        sig->rsa_signature.revocation_counter = rev_ctr;
        pollist = (lcp_list_t *)add_tpm20_signature(&(pollist->tpm20_policy_list),
                                        sig, TPM_ALG_RSASSA);
        if ( pollist == NULL ) {
            free(sig);
            return 1;
        }

        if ( no_sigblock ) {
            memset(get_tpm20_sig_block(&(pollist->tpm20_policy_list)),
                           0, sig->rsa_signature.pubkey_size);
        }
        else {
            if ( !rsa_sign_list_data(&(pollist->tpm20_policy_list), privkey_file) ) {
                free(sig);
                free(pollist);
                return 1;
            }
        }

        bool write_ok = write_tpm20_policy_list_file(pollist_file,
                                &(pollist->tpm20_policy_list));

        free(sig);
        free(pollist);
        return write_ok ? 0 : 1;
    }
    else if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_ECDSA ) {
        LOG("sign: sig_alg == TPM_ALG_ECDSA\n");
        EC_KEY *eckey = EC_KEY_new();
        EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
        EC_KEY_set_group(eckey,ecgroup);

        if ( !EC_KEY_generate_key(eckey) ) {
            ERROR("Error: EC_KEY_generate_key error\n");
            return 1;
        }
        const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
        if( pubkey == NULL) {
            ERROR("Error: EC_KEY_get0_public_key error\n");
            return 1;
        }

        lcp_signature_t2 *sig = read_ecdsa_pubkey(pubkey, ecgroup);
        sig->ecc_signature.revocation_counter = rev_ctr;
        pollist = (lcp_list_t *)add_tpm20_signature(&(pollist->tpm20_policy_list),
                                        sig, TPM_ALG_ECDSA);
        if ( pollist == NULL ) {
            free(sig);
            return 1;
        }

        if ( no_sigblock ) {
            memset(get_tpm20_sig_block(&(pollist->tpm20_policy_list)),
                           0, sig->ecc_signature.pubkey_size);
        }
        else {
            if ( !ecdsa_sign_tpm20_list_data(&(pollist->tpm20_policy_list), eckey) ) {
                free(sig);
                free(pollist);
                return 1;
            }
        }

        bool write_ok = write_tpm20_policy_list_file(pollist_file,
                                &(pollist->tpm20_policy_list));

        free(sig);
        free(pollist);
        return write_ok ? 0 : 1;
    }
    else if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_SM2 ) {
        LOG("sign: sig_alg == TPM_ALG_SM2\n");
        return 1;
    }

    return 1;
}

static int addsig(void)
{
    /* read existing policy list file */
    bool no_sigblock_ok = true;
    lcp_list_t *pollist = read_policy_list_file(pollist_file, false,
            &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    uint16_t  version ;
    memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
    if (version != LCP_TPM20_POLICY_LIST_VERSION )
        return 1;

    LOG("signature: version == 0x0200\n");
    lcp_signature_t2 *sig = get_tpm20_signature(&(pollist->tpm20_policy_list));
    if ( sig == NULL ) {
        free(pollist);
        return 1;
    }
    /* check public key size */
    if ( (sig->rsa_signature.pubkey_size != 128 /* 1024 bits */)
            && (sig->rsa_signature.pubkey_size != 256 /* 2048 bits */)
            && (sig->rsa_signature.pubkey_size != 384 /* 3072 bits */) ) {
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

    if ( len != sig->rsa_signature.pubkey_size ) {
        ERROR("Error: signature file size doesn't match public key size\n");
        free(pollist);
        free(data);
        return 1;
    }

    /* verify that this sigblock actually matches the policy list */
    LOG("verifying signature block...\n");
    if ( !verify_signature((const unsigned char *)&(pollist->tpm20_policy_list),
                get_tpm20_policy_list_size(&(pollist->tpm20_policy_list))
                        - sig->rsa_signature.pubkey_size,
                sig->rsa_signature.pubkey_value, sig->rsa_signature.pubkey_size,
                data, false) ) {
        ERROR("Error: signature file does not match policy list\n");
        free(pollist);
        free(data);
        return 1;
    }
    LOG("signature file verified\n");

    /* data is big-endian and policy needs little-endian, so reverse */
    for ( unsigned int i = 0; i < sig->rsa_signature.pubkey_size; i++ )
        *(get_tpm20_sig_block(&(pollist->tpm20_policy_list)) + i) =
                *(data + (sig->rsa_signature.pubkey_size - i - 1));

    if ( verbose ) {
        LOG("signature:\n");
        display_tpm20_signature("    ", sig,
                pollist->tpm20_policy_list.sig_alg, false);
    }

    bool write_ok = write_tpm20_policy_list_file(pollist_file,
                            &(pollist->tpm20_policy_list));

    free(pollist);
    free(data);
    return write_ok ? 0 : 1;
}

static int show(void)
{
    /* read existing file */
    bool no_sigblock_ok = true;
    lcp_list_t *pollist = read_policy_list_file(files[0], false,
            &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    uint16_t  version ;
    memcpy((void*)&version,(const void *)pollist,sizeof(uint16_t));
    if (version != LCP_TPM20_POLICY_LIST_VERSION )
        return 1;

    LOG("show: version == 0x0200\n");
    DISPLAY("policy list file: %s\n", files[0]);
    display_tpm20_policy_list("", &(pollist->tpm20_policy_list), false);

    if ( pollist->tpm20_policy_list.sig_alg == LCP_POLSALG_RSA_PKCS_15 &&
         !no_sigblock_ok ) {
        if ( verify_tpm20_pollist_sig(&(pollist->tpm20_policy_list)) )
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
        LOG("c=%c\n",c);
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

        case 'o':            /* out */
            strlcpy(pollist_file, optarg, sizeof(pollist_file));
            LOG("cmdline opt: out: %s\n", pollist_file);
            break;

        case 'a':
            strlcpy(sigalg_name, optarg, sizeof(sigalg_name));
            LOG("cmdline opt: sigalg: %s\n", sigalg_name);
            sigalg_type = str_to_sig_alg(sigalg_name, version);
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
        if ( sigalg_type == TPM_ALG_RSASSA || sigalg_type == LCP_POLSALG_RSA_PKCS_15 ) { 
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
