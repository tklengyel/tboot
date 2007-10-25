/*
 * param.c: support functions for parsing command line parameters
 *
 * Copyright (c) 2006-2007, Intel Corporation
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
#include <string.h>
#include <getopt.h>
#define PRINT   printf
#include "../include/uuid.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

static const char *help[] = {
    "tb_polgen --create --uuid vmm|dom0\n",
    "                   [--policy_type nonfatal|continue|halt]\n",
    "                   --hash_type any|hash\n",
    "                   --file policy_file\n",
    "                   [--cmdline \"command line\"]\n",
    "                   [--verbose]\n",
    "                   [input_file1 ...]\n",
    "tb_polgen --show   --file policy_file\n",
    "                   [--verbose]\n",
    "tb_polgen --help\n",
    NULL
};

/*
 * Define storage for user input parameter pointers
 */
bool verbose = false;

static struct option long_options[] =
{
    /* major sub-commands */
    {"help",         no_argument,          NULL,    'H'},

    {"create",       no_argument,          NULL,    'C'},
    {"show",         no_argument,          NULL,    'S'},

    {"uuid",         required_argument,    NULL,    'u'},
    {"policy_type",  required_argument,    NULL,    'p'},
    {"hash_type",    required_argument,    NULL,    'h'},
    {"file",         required_argument,    NULL,    'f'},
    {"cmdline",      required_argument,    NULL,    'c'},

    {"verbose",      no_argument,          (int*)&verbose, true},
    {0, 0, 0, 0}
};

typedef struct {
    char       *name;
    /* should be union, but then can't statically initialize */
    int     int_opt;
    uuid_t  uuid_opt;
} option_table_t;

static option_table_t policy_type_opts[] = {
    {"nonfatal",     int_opt : TB_POLTYPE_CONT_NON_FATAL},
    {"continue",     int_opt : TB_POLTYPE_CONT_VERIFY_FAIL},
    {"halt",         int_opt : TB_POLTYPE_HALT},
    {NULL}
};

static option_table_t hash_type_opts[] = {
    {"hash",         int_opt : TB_HTYPE_HASHONLY},
    {"any",          int_opt : TB_HTYPE_ANY},
    {NULL}
};

static option_table_t uuid_opts[] = {
    {"vmm",          uuid_opt : TBPOL_VMM_UUID},
    {"dom0",         uuid_opt : TBPOL_DOM0_UUID},
    {NULL}
};

static bool parse_int_option(option_table_t *table, char *optarg, int *option)
{
    if ( option == NULL ) {
        info_msg("NULL option\n");
        return false;
    }
    info_msg("optarg = %s\n", optarg);

    while ( table->name != NULL ) {
        if ( strcasecmp(table->name, optarg) == 0 ) {
            *option = table->int_opt;
            return true;
        }
        table++;
    }
    return false;
}

static bool parse_uuid_option(option_table_t *table, char *optarg,
                              uuid_t *option)
{
    if ( option == NULL ) {
        info_msg("NULL option\n");
        return false;
    }
    info_msg("optarg = %s\n", optarg);

    while ( table->name != NULL ) {
        if ( strcasecmp(table->name, optarg) == 0 ) {
            *option = table->uuid_opt;
            return true;
        }
        table++;
    }
    return false;
}

void print_params(param_data_t *params)
{
    int i;

    info_msg("params:\n");
    info_msg("\t cmd = %d\n", params->cmd);
    info_msg("\t uuid = ");
    if ( verbose ) print_uuid(&params->uuid); info_msg("\n");
    info_msg("\t policy_type = %d\n", params->policy_type);
    info_msg("\t hash_type = %d\n", params->hash_type);
    info_msg("\t policy_file = %s\n", params->policy_file);
    info_msg("\t cmdline = %s\n", params->cmdline);
    for ( i = 0; i < params->num_infiles; i++ )
        info_msg("\t infile[%d] = %s\n", i, params->infiles[i]);
}

static bool validate_params(param_data_t *params)
{
    static const uuid_t empty_uuid = {0};

    switch( params->cmd ) {
        case POLGEN_CMD_NONE:
            error_msg("Missing command argument\n");
            return false;
        case POLGEN_CMD_CREATE:
            if ( are_uuids_equal(&params->uuid, &empty_uuid) ||
                 params->hash_type == -1 ||
                 strlen(params->policy_file) == 0 ) {
                error_msg("Missing options for --create command\n");
                print_params(params);
                return false;
            }
            if ( params->hash_type != TB_HTYPE_ANY &&
                 params->num_infiles == 0 ) {
                error_msg("Missing options for --create command\n");
                print_params(params);
                return false;
            }
            return true;
        case POLGEN_CMD_SHOW:
            if ( strlen(params->policy_file) == 0 ) {
                error_msg("Missing options for --show command\n");
                print_params(params);
                return false;
            }
            return true;
        case POLGEN_CMD_HELP:
            return true;
        default:
            error_msg("Unknown command\n");
            print_params(params);
            return false;
    }

    return false;
}

#define HANDLE_MULTIPLE_CMDS(cmd)                              \
    if ( (cmd) != POLGEN_CMD_NONE ) {                          \
        error_msg("Only one command can be specified\n");  \
        return false;                                          \
    }

bool parse_input_params(int argc, char **argv, param_data_t *params)
{
    int c;
    int option_index = 0;

    /* defaults */
    params->cmd = POLGEN_CMD_NONE;
    memset(&params->uuid, sizeof(params->uuid), 0);
    params->policy_type = -1;
    params->hash_type = -1;
    params->policy_file[0] = '\0';
    params->cmdline[0] = '\0';
    params->num_infiles = 0;

    while ( true ) {
        c = getopt_long_only(argc, argv, "HCSp:h:u:f:c:", long_options,
                             &option_index);
        if ( c == -1 )     /* no more args */
            break;

        switch (c) {
            /* commands */
            case 'H':                       /* --help */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_HELP;
                return true;
            case 'C':                       /* --create */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_CREATE;
                break;
            case 'S':                       /* --show */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_SHOW;
                break;
            /* options */
            case 'u':                       /* --uuid */
                if ( !parse_uuid_option(uuid_opts, optarg, &params->uuid) ) {
                    error_msg("Unknown --uuid option\n");
                    return false;
                }
                break;
            case 'p':                       /* --policy_type */
                if ( !parse_int_option(policy_type_opts, optarg,
                                       (int *)&params->policy_type) ) {
                    error_msg("Unknown --policy_type option\n");
                    return false;
                }
                break;
            case 'h':                       /* --hash_type */
                if ( !parse_int_option(hash_type_opts, optarg,
                                       (int *)&params->hash_type) ) {
                    error_msg("Unknown --hash_type option\n");
                    return false;
                }
                break;
            case 'f':                       /* --file */
                if ( optarg == NULL ) {
                    error_msg("Misssing filename for --file option\n");
                    return false;
                }
                strncpy(params->policy_file, optarg,
                        sizeof(params->policy_file));
                params->policy_file[sizeof(params->policy_file)-1] = '\0';
                break;
            case 'c':                       /* --cmdline */
                if ( optarg == NULL ) {
                    error_msg("Misssing string for --cmdline option\n");
                    return false;
                }
                strncpy(params->cmdline, optarg, sizeof(params->cmdline));
                params->cmdline[sizeof(params->cmdline)-1] = '\0';
                break;
            default:
                break;
        }
    }

    /* any arguments left are input files to be hashed */
    while ( optind < argc &&
            (params->num_infiles < ARRAY_SIZE(params->infiles)) ) {
        strncpy(params->infiles[params->num_infiles], argv[optind],
                sizeof(params->infiles[params->num_infiles]));
        params->infiles[params->num_infiles]
                       [sizeof(params->infiles[params->num_infiles])-1] = '\0';
        params->num_infiles++;
        optind++;
    }

    return validate_params(params);
}

void display_help_msg(void)
{
    int    i;
    
    for ( i = 0; help[i] != NULL; i++ )
        printf(help[i]);
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
