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
 *   crtpol.c
 *
 *   Command: lcp_crtpol
 *
 *   This command can create the LCP policy.
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#define PRINT   printf
#include "../include/uuid.h"
#include "../include/lcp.h"
#include "lcptools.h"
#include "lcputils.h"

#define MAX_LISTNUM 2
#define BUFFER_SIZE 1024

static uint8_t pol_type = 0xff;
static uint32_t alg = LCP_POLHALG_SHA1;
static uint8_t ver = 0;
static uint32_t pcf_val = 0;
static uint8_t sinit_revoc = 0;
static char *pol_file = NULL;
static char *mle_file = NULL;
static char *pol_data_file = NULL;
static char *srtm_file = NULL;
static int help_input = 0;

static const char * short_option = "ht:a:v:s:m:o:b:";
static struct option longopts[]= {
    {"sr", 1, 0, 'n'},
    {"pcf", 1, 0, 'p'},
    {0, 0, 0, 0},
};

static const char *usage_string = "lcp_crtpol -t policy_type [-a hashalg] "
              "[-v version] [-sr SINIT revocation_counter] [-s srtm_file] "
              "[-m mle_file] [-o policyfile] [-b policydata_file] [-h]\n";

static const char *option_strings[] = {
        "-t Policy type: uint8/string.\n"
            "\tPolicy type is:\n"
            "\tLCP_POLTYPE_HASHONLY: 0 or \"hashonly\" \n"
            "\tLCP_POLTYPE_UNSIGNED: 1 or \"unsigned\" \n"
            "\tLCP_POLTYPE_SIGNED: 2 or \"signed\" \n"
            "\tLCP_POLTYPE_ANY: 3 or \"any\" \n"
            "\tLCP_POLTYPE_FORCEOWNERPOLICY: 4 or \"forceowner\" \n",
        "-a algorithm: uint8/string. algorithm used in the policy.\n"
            "\tAlgorithm choice:\n"
            "\t\tLCP_POLHALG_SHA1: 0 or \"sha1\" \n"
            "\tCurrently we only support SHA-1 algorithm.\n",
        "-v version: uint8. version number.\n"
            "\tCurrently 0 or 1 is allowed.\n",
        "-s PConf file name: String. File name of PConf data.\n",
        "-m MLE hash file name: String. File containing the MLE hashes.\n",
        "-o LCPPOLICY file name: String. File to save the output Policy.\n",
        "-b LCPPOLICYDATA file name: String. File to save Policy data.\n",
        "-sr SINIT Revocation count number: uint8.\n",
        "-pcf Policy Control Field: uint32.\n",
        "-h help. Will print out this help message.\n",
        NULL
};

static param_option_t poltype_option_table[] = {
    {"hashonly", LCP_POLTYPE_HASHONLY},
    {"unsigned", LCP_POLTYPE_UNSIGNED},
    {"signed", LCP_POLTYPE_SIGNED},
    {"any", LCP_POLTYPE_ANY},
    {"forceowner", LCP_POLTYPE_FORCEOWNERPOLICY},
    {NULL, -1}
};

/*
 * function: parse_cmdline
 * description: parse the input of commandline
 */
static int
parse_cmdline(int argc, const char * argv[])
{
    int c;
    unsigned int temp = 0;

    while ((c = getopt_long_only(argc, (char ** const)argv,
                       short_option, longopts, NULL)) != -1)
        switch (c) {
            case 't':
                /* check whether user inputs the string for policy type*/
                temp = parse_input_option(poltype_option_table, optarg);

                /*
                 * if not, then the users should input the 0~4 number,
                 */
                if ( temp == (unsigned int)-1 )
                    if ( strtonum(optarg, &temp) )
                        return LCP_E_INVALID_PARAMETER;

                if ( temp > 4 ) {
                        log_error("policy type out of range.\n");
                        return LCP_E_INVALID_PARAMETER;
                }
                pol_type =  temp;
                break;

            case 'a':
                if ( strcasecmp(optarg, "sha1") == 0 )
                    alg = LCP_POLHALG_SHA1;
                else if ( strtonum(optarg, &alg) )
                    return LCP_E_INVALID_PARAMETER;
                if ( alg != LCP_POLHALG_SHA1 ) {
                    log_error("Policy algorithm not supported!\n");
                    return LCP_E_INVALID_PARAMETER;
                }
                break;

            case 'v':
                if ( strtonum(optarg, &temp) )
                    return LCP_E_INVALID_PARAMETER;
                /*
                 * Currently we only support version 0 or 1.
                 */
                if ( temp > 1 ) {
                    log_error("version %d is not supported!\n", ver);
                    return LCP_E_INVALID_PARAMETER;
                }
                ver = temp;
                break;

            case 's':
                srtm_file = optarg;
                break;

            case 'm':
                mle_file = optarg;
                break;

            case 'o':
                pol_file = optarg;
                break;

            case 'b':
                pol_data_file = optarg;
                break;

            case 'n':
                if ( strtonum(optarg, &temp) )
                    return LCP_E_INVALID_PARAMETER;
                if ( temp > 0xff )
                    return LCP_E_INVALID_PARAMETER;
                sinit_revoc = temp;
                break;

            case 'p':
                if ( strtonum(optarg, &pcf_val) )
                    return LCP_E_INVALID_PARAMETER;
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

/* read data from file */
static int
read_data(const char *filename, unsigned int *size, unsigned char *data)
{
    FILE *pfile = NULL;
    unsigned int len;

    if ( filename == NULL || data == NULL )
        return -1;

    pfile = fopen(filename, "rb");
    if ( pfile == NULL ) {
        //log_error("Can't open MLE/PConf file\n");
        return -1;
    }
    fseek(pfile, 0, SEEK_END);
    len = ftell(pfile);
    fseek(pfile, 0, SEEK_SET);
    if ( len > BUFFER_SIZE ) {
        log_error("the file %s is too long. File size is %d.\n", filename, len);
        fclose(pfile);
        return -1;
    }
    if ( len != fread(data, 1, len, pfile) ) {
        fclose(pfile);
        log_error("Read data from file error!\n");
        return -1;
    }
    *size = len;
    fclose(pfile);
    return 0;
}

/* save data to file */
static int
save_data(unsigned char *data, unsigned int len, const char *file)
{
    FILE *pfile = NULL;

    if ( data == NULL || file == NULL )
        return -1;

    pfile = fopen(file, "wb");
    if ( pfile == NULL ) {
        log_error("Open file %s error!\n", file);
        return -1;
    }
    if ( len != fwrite(data, 1, len, pfile) ) {
        fclose(pfile);
        log_error("Write data into file error!\n");
        return -1;
    }
    fclose(pfile);
    return 0;
}

static int
convert_hashes(unsigned int mle_len_ascii,
	       unsigned char *mle_data_ascii,
	       unsigned int *mle_len,
	       unsigned char *mle_data)
{
    unsigned long data;
    unsigned char *curr, *next;
    char tmp[3];

    curr = mle_data_ascii;
    *mle_len = 0;
    while ( curr < (mle_data_ascii + mle_len_ascii) ) {
        errno = 0;
	data = 0;
        data = strtoul((char *)curr, (char **)&next, 16);

	/* overflow, which means there were no spaces in input */
	if ( errno == ERANGE || (data & ~0xff) != 0 ) {
	    /* copy 2 chars into separate buffer and convert them */
	    tmp[0] = *curr;  tmp[1] = *(curr+1);  tmp[2] = '\0';
	    data = strtoul(tmp, NULL, 16);
	    next = curr + 2;
	}
	else if ( errno != 0 )    /* some other error */
	    break;

	if ( next == curr )       /* done */
	    break;

	mle_data[(*mle_len)++] = (unsigned char)data;
	curr = next;
    }

    if ( curr < (mle_data_ascii + mle_len_ascii - 1) )
        return -1;
    else
        return 0;
}

/* create policy and policy data */
static lcp_result_t
create_policy(lcp_policy_t *lcppolicy,
              unsigned char *mledata,
              unsigned int mlelen,
              unsigned char *pconfdata,
              unsigned int pconflen,
              unsigned char *policy,
              unsigned int *policylen,
              unsigned char *poldata,
              unsigned int *poldatalen)
{
    pdlist_src_t listdata[MAX_LISTNUM];
    unsigned int listnum = 0;
    uint32_t poldataver = 0;
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

    switch (pol_type) {
        case LCP_POLTYPE_HASHONLY:
            if ( (mledata == NULL) || (mlelen == 0) ) {
                log_error("Please use MLE file to input the HASH value!\n");
                return LCP_E_INVALID_PARAMETER;
            }
            if ( (ret_value = lcp_create_policy(lcppolicy,
                    mlelen, mledata,  policylen, policy)) != LCP_SUCCESS ) {
                log_error("create policy error\n");
                return ret_value;
            }
            break;

        case LCP_POLTYPE_UNSIGNED:
            if ( ((mledata == NULL) || (mlelen == 0))
                    && ((pconfdata == NULL) || (pconflen == 0)) ) {
                log_error("Haven't input MLE file or PConf file.\n");
                return LCP_E_INVALID_PARAMETER;
            }

            if ( mlelen != 0 ) {
                //print_hexmsg("the mle data is:\n", mlelen, mledata);
                listdata[listnum].algorithm = alg;
                listdata[listnum].type = LCP_POLDESC_MLE_UNSIGNED;
                listdata[listnum].list_version = 0;/*default value*/
                listdata[listnum].listdata_length = mlelen;
                listdata[listnum].listdata= mledata;
                listnum++;
            }
            if ( pconflen != 0 ) {
                //print_hexmsg("the pconf data is:\n", pconflen, pconfdata);
                listdata[listnum].algorithm = alg;
                listdata[listnum].type= LCP_POLDESC_PCONF_UNSIGNED;
                listdata[listnum].list_version = 0;/*default value*/
                listdata[listnum].listdata_length= pconflen;
                listdata[listnum].listdata = pconfdata;
                listnum++;
            }
            if ( (ret_value = lcp_create_unsigned_poldata(poldataver,
                                listnum, listdata, poldatalen,
                                poldata)) != LCP_SUCCESS ) {
                log_error("create policy data error\n");
                return ret_value;
            }
            if ( (ret_value = lcp_create_policy(lcppolicy,
                                *poldatalen, poldata, policylen,
                                policy)) != LCP_SUCCESS ) {
                log_error("create policy error\n");
                return ret_value;
            }
            break;

        case LCP_POLTYPE_ANY:
            if ( (ret_value = lcp_create_policy(lcppolicy,
                        0, NULL, policylen, policy)) != LCP_SUCCESS ) {
                log_error("create policy error\n");
                return ret_value;
            }
            break;

        case LCP_POLTYPE_FORCEOWNERPOLICY:
            if ( (ret_value = lcp_create_policy(lcppolicy,
                        0, NULL,  policylen, policy)) != LCP_SUCCESS ) {
                log_error("create policy error\n");
                return ret_value;
            }
            break;

        case LCP_POLTYPE_SIGNED:
        default:
            log_error("Unsupported Policy type!\n");
            return LCP_E_INVALID_PARAMETER;
    }
    return LCP_SUCCESS;
}

static unsigned char policy_data[BUFFER_SIZE];
static unsigned char policy[BUFFER_SIZE];
static unsigned char mle_data_ascii[BUFFER_SIZE];
static unsigned char mle_data[BUFFER_SIZE];
static unsigned char srtm_data[BUFFER_SIZE];

int
main (int argc, char *argv[])
{
    unsigned int pol_len = BUFFER_SIZE;
    unsigned int pol_data_len = BUFFER_SIZE;
    unsigned int srtm_len = 0;
    unsigned int mle_len = 0, mle_len_ascii = 0;
    lcp_policy_t lcppolicy;
    lcp_result_t ret_value = LCP_E_COMD_INTERNAL_ERR;

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

    if ( pol_type == 0xff ) {
        log_error("No Policy type value has been input. "\
            "Must input Policy type value to create Policy Object! \n");
        ret_value = LCP_E_INVALID_PARAMETER;
        goto _error_end;
    }

    lcppolicy.version = ver;
    lcppolicy.hash_alg = alg;
    lcppolicy.policy_type = pol_type;
    lcppolicy.sinit_revocation_counter = sinit_revoc;
    lcppolicy.reserved[0] = 0;
    lcppolicy.reserved[1] = 0;
    lcppolicy.reserved[2] = 0;
    lcppolicy.policy_control = pcf_val;

    if ( mle_file ) {
        /* read ASCII hash data */
        if ( read_data(mle_file, &mle_len_ascii, mle_data_ascii) < 0 ) {
            log_error("Can't open mle file.\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto _error_end;
        }
	/* ensure that convert_hashes() won't overrun the buffer */
	mle_data_ascii[BUFFER_SIZE - 1] = '\0';
	/* convert ASCII hashes to binary */
	if ( convert_hashes(mle_len_ascii, mle_data_ascii, &mle_len,
			    mle_data) < 0 ) {
            log_error("Can't convert ASCII MLE hashes to binary.\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto _error_end;
	}
    }

    if ( srtm_file ) {
        if ( read_data(srtm_file, &srtm_len, srtm_data) < 0 ) {
            log_error("Can't open PConf file.\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto _error_end;
        }
    }

    /*
     * Create policy data and policy.
     */
    if ( (ret_value = create_policy(&lcppolicy,
                         mle_data, mle_len, srtm_data, srtm_len,
                         policy, &pol_len, policy_data,
                         &pol_data_len)) != LCP_SUCCESS ) {
        log_error("Create policy data and policy error!\n");
        goto _error_end;
    }
    /*
     * Write policy into file.
     */
    if ( pol_file != NULL ) {
        if ( save_data(policy, pol_len, pol_file) < 0 ) {
            log_error("Write policy into file error!\n");
            ret_value = LCP_E_COMD_INTERNAL_ERR;
            goto _error_end;
        }
    } else
        print_hexmsg("the policy is:\n", pol_len, policy);

    if ( pol_type == LCP_POLTYPE_UNSIGNED ) {
        /*
         * Write policy data into file.
         */
        if ( pol_data_file != NULL ) {
            if ( save_data(policy_data, pol_data_len, pol_data_file) < 0 ) {
                log_error("Write policy data into file error!\n");
                ret_value = LCP_E_COMD_INTERNAL_ERR;
                goto _error_end;
            }
        } else
            print_hexmsg("the policy data is:\n", pol_data_len, policy_data);
        printf("Successfully create the policy and the policy data\n");
    } else
        printf("Successfully create the policy\n");

    return LCP_SUCCESS;

_error_end:
    /*
     * Error when execution.
     */
    log_error("\nCommand CrtPol failed:\n");
    print_error(ret_value);
    return ret_value;
}
