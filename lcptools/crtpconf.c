/*
 * Copyright 2001 - 2010 Intel Corporation. All Rights Reserved. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *   crtpconf.c
 *
 *   Command: lcp_crtpconf.
 *
 *   This command can create PConf data for use when creating LCP policy data.
 *
 */


#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#define PRINT   printf
#include "../include/uuid.h"
#include "../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"


#define MAX_INDEX 24

static uint8_t locality = 0x1f;
static char *file = NULL;
static unsigned char *pcr_val = NULL;
static int help_input = 0;

static const char *short_option = "hp:f:";
static const char *usage_string = "lcp_crtpconf "\
                "-p PCR_index1,PCR_index2,...,PCR_indexn "\
                "[-f filename] [-h]\n";

static const char * option_strings[] ={
        "-p PCR_Index1,PCR_Index2,...: uint8. \n",
        "-f file name of SRTMMeasurement: string. Content is appended.\n",
        "-h help. Will print out this help message.\n",
        0
};

/* function: parse_cmdline
 * description: parse the input of commandline
 */
static int
parse_cmdline(int argc, const char * argv[])
{
    int c;

    while (((c = getopt(argc, (char ** const)argv, short_option)) != -1))
        switch (c){
            case 'p':
	      pcr_val = (unsigned char *)optarg;
                break;

            case 'f':
                file = optarg;
                break;

            case 'h':
                help_input = 1;
                break;

            default:
                return  LCP_E_NO_SUCH_PARAMETER;
        }

    if ( optind < argc )
        return LCP_E_INVALID_PARAMETER;

    return LCP_SUCCESS;
}

int
main(int argc, char *argv[])
{
    uint16_t i = 0;
    uint32_t index[MAX_INDEX] = {0};
    uint32_t idx_num = 0;
    unsigned char *pcr_num[MAX_INDEX] = {NULL};
    FILE *p_file = NULL;
    unsigned char* srtm_data = NULL;
    uint32_t data_len = 0;
    TPM_LOCALITY_SELECTION local_sel;

    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;
    uint32_t temp = 0;

    /*
     * No parameter input will print out the help message.
     */
    if ( argc == 1 ) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

    /*
     * Parse the parameters input to decide
     * what parameters will be passed to TSS API.
     */
    ret_value =  parse_cmdline(argc, (const char **)argv);
    if ( ret_value )
        goto _error_end;

    /*
     * If user input -h(help), just print guide to
     * users and ignore other parameters.
     */
    if ( help_input ) {
        print_help(usage_string, option_strings);
        return LCP_SUCCESS;
    }

    /*
     * Parse command line string to get the PCR numbers.
     */
    if ( pcr_val == NULL ) {
        log_error("Must input PCR numbers to creat PConf data.\n");
        ret_value = LCP_E_INVALID_PARAMETER;
        goto _error_end;
    }

    for (i = 0; i < MAX_INDEX; i++) {
        pcr_num[i] = (unsigned char *)malloc(10);
        if ( pcr_num[i] == NULL ) {
            ret_value = LCP_E_OUTOFMEMORY;
            goto _error_end;
        }
    }
    if ( str_split((char *)pcr_val, (char **)&pcr_num, &idx_num) < 0 ) {
        ret_value = LCP_E_INVALID_PARAMETER;
        goto _error_end;
    }
    for ( i = 0; i < idx_num; i++ ) {
      if ( strtonum((char *)pcr_num[i], &temp) < 0 ) {
            ret_value = LCP_E_INVALID_PARAMETER;
            goto _error_end;
        }
        if ( temp > 23 ) {
            ret_value = LCP_E_INVALID_PARAMETER;
            goto _error_end;
        }
        index[i] = temp;
    }

    local_sel = (TPM_LOCALITY_SELECTION)locality;
    ret_value = lcp_create_pconf(idx_num,
                     index, 0, NULL, local_sel, &data_len, &srtm_data);
    if ( ret_value == LCP_SUCCESS ) {
        if ( file != NULL ) {
            /*
             * Write Platform configure data to file.
             */
            p_file = fopen(file, "a");
            if ( !p_file ) {
                log_error("Open file %s error!\n", file);
                ret_value = LCP_E_COMD_INTERNAL_ERR;
                goto _error_end;
            }
            log_debug("Data length is %d.\n", data_len);
            if ( data_len != fwrite(srtm_data, 1, data_len, p_file) ) {
                log_error("Write SRTM data into file error!"\
                        "Data length is %d.\n",data_len);
                fclose(p_file);
                ret_value = LCP_E_COMD_INTERNAL_ERR;
                goto _error_end;
            }
            fclose(p_file);
        } else
            print_hexmsg("the PConf data is:\n", data_len, srtm_data);
        if(srtm_data)
            free(srtm_data);
    } else
        goto _error_end;

    return LCP_SUCCESS;
_error_end:
    /*
     * Error when execute.
     */
    for (i = 0; i < MAX_INDEX; i++)
        free(pcr_num[i]);
    free(srtm_data);
    log_error("\nCommand CrtPConf failed:\n");
    print_error(ret_value);
    return ret_value;
}
