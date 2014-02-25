/*
 * pconf_elt.c: platform config policy element (LCP_PCONF_ELEMENT) plugin
 *
 * Copyright (c) 2009 - 2010, Intel Corporation
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
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <byteswap.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"

#define NR_PCRS             24

#define MAX_PCR_INFOS       32

/*
 * TPM_PCR_INFO_SHORT
 * (from tboot/tpm.{h,c}
 */

typedef struct __packed {
    uint16_t    size_of_select;
    uint8_t     pcr_select[3];
} tpm_pcr_selection_t;

typedef uint8_t tpm_locality_selection_t;

#define TPM_DIGEST_SIZE          20
typedef struct __packed {
    uint8_t     digest[TPM_DIGEST_SIZE];
} tpm_digest_t;

typedef tpm_digest_t tpm_composite_hash_t;
typedef tpm_digest_t tpm_pcr_value_t;

typedef struct __packed {
    tpm_pcr_selection_t   select;
    uint32_t              value_size;
    tpm_pcr_value_t       pcr_value[];
} tpm_pcr_composite_t;

typedef struct __packed {
    tpm_pcr_selection_t         pcr_selection;
    tpm_locality_selection_t    locality_at_release;
    tpm_composite_hash_t        digest_at_release;
} tpm_pcr_info_short_t;

/* need to define TPM_PCR_INFO_SHORT before including lcp2.h */
#define TPM_PCR_INFO_SHORT tpm_pcr_info_short_t
#include "../include/lcp2.h"
#include "polelt_plugin.h"
#include "lcputils2.h"

static unsigned int nr_pcr_infos;
static tpm_pcr_info_short_t pcr_infos[MAX_PCR_INFOS];

static unsigned int nr_pcrs;
static unsigned int pcrs[NR_PCRS];
static tb_hash_t digests[NR_PCRS];

static bool parse_pconf_line(const char *line)
{
    if ( nr_pcrs == NR_PCRS )
        return false;

    /* skip any leading whitespace and non-digits */
    while ( *line != '\0' && (isspace(*line) || !isdigit(*line)) )
        line++;

    /* get PCR # */
    pcrs[nr_pcrs] = (unsigned int)strtoul(line, (char **)&line, 10);
    if ( pcrs[nr_pcrs] >= NR_PCRS ) {
        ERROR("Error: invalid PCR value\n");
        return false;
    }
    LOG("parsed PCR: %u\n", pcrs[nr_pcrs]);

    /* skip until next digit */
    while ( *line != '\0' && !isxdigit(*line) )
        line++;

    if ( !parse_line_hashes(line, &digests[nr_pcrs]) )
        return false;

    nr_pcrs++;

    return true;
}

static bool make_pcr_info(unsigned int nr_pcrs, unsigned int pcrs[],
                          tb_hash_t digests[], tpm_pcr_info_short_t *pcr_info)
{
    unsigned int i;
    /* don't use TSS Trspi_xxx fns to create this so that there is no
       runtime dependency on a TSS */

    /* fill in pcrSelection */
    /* TPM structures are big-endian, so byte-swap */
    pcr_info->pcr_selection.size_of_select = bswap_16(3);
    memset(&pcr_info->pcr_selection.pcr_select, 0,
           sizeof(pcr_info->pcr_selection.pcr_select));
    for ( i = 0; i < nr_pcrs; i++ )
        pcr_info->pcr_selection.pcr_select[pcrs[i]/8] |= 1 << (pcrs[i] % 8);

    /* set locality to default (0x1f) */
    pcr_info->locality_at_release = 0x1f;

    /*
     * digest is hash of TPM_PCR_COMPOSITE
     */
    size_t pcr_comp_size = offsetof(tpm_pcr_composite_t, pcr_value) +
                           nr_pcrs * sizeof(tpm_pcr_value_t);
    tpm_pcr_composite_t *pcr_comp = (tpm_pcr_composite_t *)malloc(pcr_comp_size);
                                      
    if ( pcr_comp == NULL )
        return false;
    memcpy(&pcr_comp->select, &pcr_info->pcr_selection, sizeof(pcr_comp->select));
    pcr_comp->value_size = bswap_32(nr_pcrs * sizeof(tpm_pcr_value_t));
    /* concat specified digests */
    for ( i = 0; i < nr_pcrs; i++ ) {
        memcpy(&pcr_comp->pcr_value[i], &digests[i],
               sizeof(pcr_comp->pcr_value[0]));
    }
    /* then hash it */
    tb_hash_t hash;
    if ( !hash_buffer((uint8_t *)pcr_comp, pcr_comp_size, &hash,
                      TB_HALG_SHA1_LG) ) {
        free(pcr_comp);
        return false;
    }
    /* then copy it */
    memcpy(&pcr_info->digest_at_release, &hash,
           sizeof(pcr_info->digest_at_release));

    free(pcr_comp);
    return true;
}

static bool cmdline_handler(int c, const char *opt)
{
    if ( c != 0 ) {
        ERROR("Error: unknown option for pconf type\n");
        return false;
    }

    nr_pcrs = 0;
    memset(&pcrs, 0, sizeof(pcrs));
    memset(&digests, 0, sizeof(digests));

    /* pconf files */
    LOG("cmdline opt: pconf file: %s\n", opt);
    if ( !parse_file(opt, parse_pconf_line) )
        return false;

    if ( !make_pcr_info(nr_pcrs, pcrs, digests, &pcr_infos[nr_pcr_infos++]) )
        return false;

    return true;
}

static lcp_policy_element_t *create(void)
{
    size_t data_size = sizeof(uint16_t) + nr_pcr_infos * sizeof(pcr_infos[0]);

    lcp_policy_element_t *elt = malloc(sizeof(*elt) + data_size);
    if ( elt == NULL ) {
        ERROR("Error: failed to allocate element\n");
        return NULL;
    }

    memset(elt, 0, sizeof(*elt) + data_size);
    elt->size = sizeof(*elt) + data_size;

    lcp_pconf_element_t *pconf = (lcp_pconf_element_t *)&elt->data;
    pconf->num_pcr_infos = nr_pcr_infos;
    memcpy(&pconf->pcr_infos, &pcr_infos, nr_pcr_infos * sizeof(pcr_infos[0]));

    return elt;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    lcp_pconf_element_t *pconf = (lcp_pconf_element_t *)elt->data;

    DISPLAY("%s num_pcr_infos: %u\n", prefix, pconf->num_pcr_infos);
    for ( unsigned int i = 0; i < pconf->num_pcr_infos; i++ ) {
        tpm_pcr_info_short_t *pcr_info =
                               (tpm_pcr_info_short_t *)&pconf->pcr_infos[i];
        DISPLAY("%s pcr_infos[%u]:\n", prefix, i);
        DISPLAY("%s     pcrSelect: 0x%02x%02x%02x\n", prefix,
                pcr_info->pcr_selection.pcr_select[0],
                pcr_info->pcr_selection.pcr_select[1],
                pcr_info->pcr_selection.pcr_select[2]);
        DISPLAY("%s     localityAtRelease: 0x%x\n", prefix,
                pcr_info->locality_at_release);
        DISPLAY("%s     digestAtRelease: ", prefix);
        print_hex("", &pcr_info->digest_at_release,
                  get_hash_size(TB_HALG_SHA1_LG));
    }
}

static polelt_plugin_t plugin = {
    "pconf",
    NULL,
    "      pconf\n"
    "        <FILE1> [FILE2] ...         one or more files containing PCR\n"
    "                                    numbers and the desired digest\n"
    "                                    of each; each file will be a PCONF\n",
    LCP_POLELT_TYPE_PCONF,
    &cmdline_handler,
    &create,
    &display
};

REG_POLELT_PLUGIN(&plugin)


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
