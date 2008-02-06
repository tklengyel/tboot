
#include <ctype.h>

/* for include/ctype.h */
unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,         /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                    /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                        /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                        /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                        /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,      /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                        /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,      /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                        /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,   /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,       /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,       /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,       /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,       /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};      /* 240-255 */


#include <compiler.h>
#include <types.h>
#include <string2.h>
#include <misc.h>

/* from init.h */

/*Used for kernel command line parameter setup */
#define MAX_PARAM_LEN 32
struct cmdline_option {
    const char *name;
    char val[MAX_PARAM_LEN];
};

/* global option array for command line */
static struct cmdline_option g_cmdline_option[] = {
    { "loglvl", "all" },
};

static char* cmdline_option_read(const char *opt)
{
    char* optval = NULL;
    int i;

    for ( i = 0; i < ARRAY_SIZE(g_cmdline_option); i++ )
    {
        if ( strcmp(g_cmdline_option[i].name, opt) != 0 )
            continue;
        optval = g_cmdline_option[i].val;
    }
    return optval;
}

void cmdline_parse(char *cmdline)
{
    char opt[100], *optval, *q;
    const char *p = cmdline;
    int i;

    if ( p == NULL )
        return;
    /* Skip whitespace and the image name. */
    while ( *p == ' ' )
        p++;
    if ( (p = strchr(p, ' ')) == NULL )
        return;

    for ( ; ; )
    {
        /* Skip whitespace. */
        while ( *p == ' ' )
            p++;
        if ( *p == '\0' )
            break;

        /* Grab the next whitespace-delimited option. */
        q = opt;
        while ( (*p != ' ') && (*p != '\0') )
        {
            if ( (q-opt) < (sizeof(opt)-1) ) /* avoid overflow */
                *q++ = *p;
            p++;
        }
        *q = '\0';

        /* Search for value part of a key=value option. */
        optval = strchr(opt, '=');
        if ( optval != NULL )
            *optval++ = '\0'; /* nul-terminate the option value */
        else
            optval = q;       /* default option value is empty string */

        for ( i = 0; i < ARRAY_SIZE(g_cmdline_option); i++ )
        {
            if ( strcmp(g_cmdline_option[i].name, opt ) != 0 )
                continue;
            strlcpy(g_cmdline_option[i].val, optval, sizeof(g_cmdline_option[i].val));
        }
    }
}

void parse_loglvl(void)
{
    extern int loglevel; /* default value is 1, print all */
    char *loglvl;

    loglvl = cmdline_option_read("loglvl");
    if ( loglvl == NULL )
        return;

    if ( strcmp(loglvl, "none") == 0 ) {
        loglevel = 0; /* print nothing */
        return;
    }
    return;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
