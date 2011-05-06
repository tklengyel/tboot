/*
 * crtpol2.c: Intel(R) TXT policy (LCP_POLICY) creation tool
 *
 * Copyright (c) 2009, Intel Corporation
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
#include "polelt_plugin.h"
#include "pol.h"
#include "poldata.h"
#include "pollist.h"
#include "lcputils2.h"

static const char help[] =
    "Usage: lcp_crtpol2 <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy (and policy data file)\n\n"
    "--create\n"
    "        [--ver <version>]       version\n"
    "        --type <any|list>       type\n"
    "        [--minver <ver>]        SINITMinVersion\n"
    "        [--rev <ctr1>[,ctrN]    revocation values (comma separated,\n"
    "                                no spaces\n"
    "        [--ctrl <pol ctrl]      policy control\n"
    "        --pol <FILE>            policy file\n"
    "        [--data <FILE>          policy data file\n"
    "        [FILE]...               policy list files\n"
    "--show\n"
    "        [--brief]               brief format output\n"
    "        [policy file]           policy file\n"
    "        [policy data file]      policy data file\n"
    "--help\n"
    "--verbose                       enable verbose output; can be\n"
    "                                specified with any command\n\n";

bool verbose = false;

static struct option long_opts[] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},

    {"create",         no_argument,          NULL,     'C'},
    {"show",           no_argument,          NULL,     'S'},

    /* options */
    {"ver",            required_argument,    NULL,     'v'},
    {"type",           required_argument,    NULL,     't'},
    {"minver",         required_argument,    NULL,     'm'},
    {"rev",            required_argument,    NULL,     'r'},
    {"ctrl",           required_argument,    NULL,     'c'},
    {"pol",            required_argument,    NULL,     'p'},
    {"data",           required_argument,    NULL,     'd'},
    {"brief",          no_argument,          NULL,     'b'},

    {"verbose",        no_argument,          (int *)&verbose, true},
    {0, 0, 0, 0}
};

uint16_t       version = LCP_DEFAULT_POLICY_VERSION;
char           policy_file[MAX_PATH] = "";
char           poldata_file[MAX_PATH] = "";
char           type[32] = "";
uint8_t        sinit_min_ver = 0;
unsigned int   nr_rev_ctrs = 0;
uint16_t       rev_ctrs[LCP_MAX_LISTS] = { 0 };
uint32_t       policy_ctrl = LCP_DEFAULT_POLICY_CONTROL;
bool           brief = false;
unsigned int   nr_files = 0;
char           files[LCP_MAX_LISTS][MAX_PATH];

static int create(void)
{
    lcp_policy_data_t *poldata = NULL;

    lcp_policy_t *pol = malloc(sizeof(*pol));
    if ( pol == NULL ) {
        ERROR("Error: failed to allocate policy\n");
        return 1;
    }
    memset(pol, 0, sizeof(*pol));
    pol->version = version;
    pol->hash_alg = LCP_POLHALG_SHA1;
    pol->sinit_min_version = sinit_min_ver;
    for ( unsigned int i = 0; i < nr_rev_ctrs; i++ )
        pol->data_revocation_counters[i] = rev_ctrs[i];
    pol->policy_control = policy_ctrl;

    if ( strcmp(type, "any") == 0 )
        pol->policy_type = LCP_POLTYPE_ANY;
    else if ( strcmp(type, "list") == 0 ) {
        pol->policy_type = LCP_POLTYPE_LIST;

        poldata = malloc(sizeof(*poldata));
        if ( poldata == NULL ) {
            ERROR("Error: failed to allocate memory\n");
            free(pol);
            return 1;
        }
        memset(poldata, 0, sizeof(*poldata));
        strlcpy(poldata->file_signature, LCP_POLICY_DATA_FILE_SIGNATURE,
                sizeof(poldata->file_signature));
        poldata->num_lists = 0;

        for ( unsigned int i = 0; i < nr_files; i++ ) {
            bool no_sigblock_ok = false;
            lcp_policy_list_t *pollist =
                        read_policy_list_file(files[i], false, &no_sigblock_ok);
            if ( pollist == NULL ) {
                free(pol);
                free(poldata);
                return 1;
            }
            poldata = add_policy_list(poldata, pollist);
            if ( poldata == NULL ) {
                free(pol);
                free(pollist);
                return 1;
            }
            free(pollist);
        }

        calc_policy_data_hash(poldata, &pol->policy_hash, pol->hash_alg);
    }

    bool ok;
    ok = write_file(policy_file, pol, get_policy_size(pol));
    if ( ok && pol->policy_type == LCP_POLTYPE_LIST )
        ok = write_file(poldata_file, poldata, get_policy_data_size(poldata));

    free(pol);
    free(poldata);
    return ok ? 0 : 1;
}

static int show(void)
{
    size_t len, pol_len = 0, poldata_len = 0;
    void *data;
    const char *pol_file = "", *poldata_file = "";
    lcp_policy_t *pol = NULL;
    lcp_policy_data_t *poldata = NULL;
    int err = 1;

    data = read_file(files[0], &len, false);
    if ( data == NULL )
        return 1;

    /* we allow files in any order or either one only, so assume that if
       first file doesn't verify as a policy then it must be policy data */
    if ( !verify_policy(data, len, true) ) {
        poldata = (lcp_policy_data_t *)data;
        poldata_len = len;
        poldata_file = files[0];
    }
    else {
        pol = data;
        pol_len = len;
        pol_file = files[0];
    }

    if ( nr_files == 2 ) {
        data = read_file(files[1], &len, false);
        if ( data == NULL )
            goto done;
        if ( pol == NULL ) {
            pol = data;
            pol_len = len;
            pol_file = files[1];
        }
        else {
            poldata = data;
            poldata_len = len;
            poldata_file = files[1];
        }
    }

    if ( pol != NULL ) {
        DISPLAY("policy file: %s\n", pol_file);
        if ( verify_policy(pol, pol_len, false) ) {
            display_policy("    ", pol, brief);
            err = 0;
        }
    }

    if ( poldata != NULL ) {
        DISPLAY("\npolicy data file: %s\n", poldata_file);
        if ( verify_policy_data(poldata, poldata_len) ) {
            display_policy_data("    ", poldata, brief);

            /* no use verifying hash if policy didn't validate or doesn't
               exist or isn't list type */
            if ( err == 0 && pol->policy_type == LCP_POLTYPE_LIST ) {
                lcp_hash_t hash;
                calc_policy_data_hash(poldata, &hash, pol->hash_alg);
                if ( memcmp(&hash, &pol->policy_hash,
                            get_lcp_hash_size(pol->hash_alg)) == 0 )
                    DISPLAY("\npolicy data hash matches policy hash\n");
                else {
                    ERROR("\nError: policy data hash does not match policy hash\n");
                    err = 1;
                }
            }
            else
                err = 1;
        }
        else
            err = 1;
    }

 done:
    free(pol);
    free(poldata);
    return err;
}


int main (int argc, char *argv[])
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
        case 'S':          /* show */
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

        case 'p':            /* policy file */
            strlcpy(policy_file, optarg, sizeof(policy_file));
            LOG("cmdline opt: pol: %s\n", policy_file);
            break;

        case 'd':            /* policy data file */
            strlcpy(poldata_file, optarg, sizeof(poldata_file));
            LOG("cmdline opt: data: %s\n", poldata_file);
            break;

        case 't':            /* type */
            strlcpy(type, optarg, sizeof(type));
            LOG("cmdline opt: type: %s\n", type);
            break;

        case 'r':            /* revocation counters */
            nr_rev_ctrs = ARRAY_SIZE(rev_ctrs);
            parse_comma_sep_ints(optarg, rev_ctrs, &nr_rev_ctrs);
            LOG("cmdline opt: rev: ");
            for ( unsigned int i = 0; i < nr_rev_ctrs; i++ )
                LOG("%u, ", rev_ctrs[i]);
            LOG("\n");
            break;

        case 'm':            /* SINITMinVersion */
            sinit_min_ver = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: minver: 0x%x (%u)\n", sinit_min_ver, sinit_min_ver);
            break;

        case 'c':            /* PolicyControl */
            policy_ctrl = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: ctrl: 0x%x\n", policy_ctrl);
            break;

        case 'b':            /* brief */
            brief = true;
            LOG("cmdline opt: brief: %u\n", brief);
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
    else if ( cmd == 'H' ) {      /* --help */
        DISPLAY("%s", help);
        return 0;
    }
    else if ( cmd == 'C' ) {      /* --create */
        if ( *type == '\0' ) {
            ERROR("Error: no type specified\n");
            return 1;
        }
        if ( strcmp(type, "list") != 0 && strcmp(type, "any") != 0 ) {
            ERROR("Error: unknown type\n");
            return 1;
        }
        if ( *policy_file == '\0' ) {
            ERROR("Error: no policy file specified\n");
            return 1;
        }
        if ( strcmp(type, "list") == 0 && *poldata_file == '\0' ) {
            ERROR("Error: list type but no policy data file specified\n");
            return 1;
        }
        if ( strcmp(type, "list") == 0 && nr_files == 0 ) {
            ERROR("Error: list type but no policy lists specified\n");
            return 1;
        }
        return create();
    }
    else if ( cmd == 'S' ) {      /* --show */
        if ( nr_files == 0 ) {
            ERROR("Error: no policy or policy data file specified\n");
            return 1;
        }
        if ( nr_files > 2 ) {
            ERROR("Error: too many files specified\n");
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
