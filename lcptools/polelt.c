/*
 * polelt.c:
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
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "polelt_plugin.h"
#include "lcputils2.h"

#define POLELT_MAX_PLUGINS      32

unsigned int     nr_polelt_plugins;
polelt_plugin_t *polelt_plugins[POLELT_MAX_PLUGINS];

polelt_plugin_t *find_polelt_plugin_by_type(uint32_t type)
{
    for ( unsigned int i = 0; i < nr_polelt_plugins; i++ ) {
        if ( type == polelt_plugins[i]->type )
            return polelt_plugins[i];
    }
    return NULL;
}

polelt_plugin_t *find_polelt_plugin_by_type_string(const char *type_str)
{
    for ( unsigned int i = 0; i < nr_polelt_plugins; i++ ) {
        if ( strcmp(type_str, polelt_plugins[i]->type_string) == 0 )
            return polelt_plugins[i];
    }
    return NULL;
}

void display_policy_element(const char *prefix, const lcp_policy_element_t *elt)
{
    polelt_plugin_t *plugin = find_polelt_plugin_by_type(elt->type);
    char new_prefix[strlen(prefix)+8];

    snprintf(new_prefix, sizeof(new_prefix), "%s\t", prefix);
    DISPLAY("%s data:\n", prefix);
    if ( plugin == NULL )
        print_hex(new_prefix, elt->data, elt->size - sizeof(*elt));
    else
        (*plugin->display)(new_prefix, elt);
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
