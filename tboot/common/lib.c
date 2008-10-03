
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
#include <stdbool.h>

/* from init.h */

/*Used for kernel command line parameter setup */
#define MAX_PARAM_LEN 32
typedef struct {
    const char *name;
    char val[MAX_PARAM_LEN];
} cmdline_option_t;

/* global option array for command line */
static cmdline_option_t g_tboot_cmdline_option[] = {
    { "loglvl", "all" },
};

static cmdline_option_t g_linux_cmdline_option[] = {
    { "vga", "n/a" },
    { "mem", "n/a" },
};

static char* cmdline_option_read(cmdline_option_t *cmdline_option,
                                 const char *opt)
{
    char* optval = NULL;
    int i;

    for ( i = 0; i < ARRAY_SIZE(cmdline_option); i++ )
    {
        if ( strcmp(cmdline_option[i].name, opt) != 0 )
            continue;
        optval = cmdline_option[i].val;
    }
    return optval;
}

static void cmdline_parse(char *cmdline, cmdline_option_t *cmdline_option)
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

        for ( i = 0; i < ARRAY_SIZE(cmdline_option); i++ )
        {
            if ( strcmp(cmdline_option[i].name, opt ) != 0 )
                continue;
            strncpy(cmdline_option[i].val, optval,
		    sizeof(cmdline_option[i].val));
        }
    }
}

void tboot_cmdline_parse(char *cmdline)
{
    cmdline_parse(cmdline, g_tboot_cmdline_option);
}

void linux_cmdline_parse(char *cmdline)
{
    cmdline_parse(cmdline, g_linux_cmdline_option);
}

void parse_tboot_loglvl(void)
{
    extern int loglevel; /* default value is 1, print all */
    char *loglvl;

    loglvl = cmdline_option_read(g_tboot_cmdline_option, "loglvl");
    if ( loglvl == NULL )
        return;

    if ( strcmp(loglvl, "none") == 0 ) {
        loglevel = 0; /* print nothing */
        return;
    }
    return;
}

static bool parse_int(char *string, int len, int *value)
{
    int i;
    int m = 10;
    int n;

    if ( value == NULL )
        return false;
    if ( string == NULL )
        return false;

    i = 0;
    if ( (len > 2) && (strlen(string) > 2) ) {
        if ( (*(string + i) == '0')
            && ((*(string + i + 1) == 'X') || (*(string + i + 1) == 'x')) ) {
            m = 16;
            i += 2;
        }
    }

    n = 0;
    for ( ; i < len && i < strlen(string); i++ ) {
        char ch;
        int d;
        ch = *(string + i);
        switch ( m ) {
            case 16:
                if ( (ch >= 'A') && (ch <= 'F') )
                    d = ch - 'A' + 10;
                else if ( (ch >= 'a') && (ch <= 'f') )
                    d = ch - 'a' + 10;
                else if ( (ch >= '0') && (ch <= '9') )
                    d = ch - '0';
                else
                    return false;
                break;
            case 10:
                if ( (ch >= '0') && (ch <= '9') )
                    d = ch - '0';
                else
                    return false;
                break;
            default:
                return false;
        }
        n = n*m + d;
    }

    *value = n;
    return true;
}

bool parse_linux_vga(void)
{
    extern int vid_mode;
    char *vga;

    vga = cmdline_option_read(g_linux_cmdline_option, "vga");
    if ( vga == NULL )
        return false;

    if ( strcmp(vga, "normal") == 0 ) {
        vid_mode = 0xFFFF;
        return true;
    }
    else if ( strcmp(vga, "ext") == 0 ) {
        vid_mode = 0xFFFE;
        return true;
    }
    else if ( strcmp(vga, "ask") == 0 ) {
        vid_mode = 0xFFFD;
        return true;
    }
    else
        return parse_int(vga, strlen(vga), &vid_mode);
}

bool parse_linux_mem(void)
{
#define MAX_INT 0x7FFFFFFF
    extern int initrd_max_mem;
    char *mem;
    int mem_value, mem_len, shift;

    mem = cmdline_option_read(g_linux_cmdline_option, "mem");
    if ( mem == NULL )
        return false;

    mem_len = strlen(mem);
    if ( !parse_int(mem, mem_len - 1, &mem_value) )
        return false;

    shift = 0;
    switch (mem[mem_len]) {
        case 'G':
        case 'g':
            shift = 30;
            break;
        case 'M':
        case 'm':
            shift = 20;
            break;
        case 'K':
        case 'k':
            shift = 10;
            break;
    }

    /* overflow */
    if ( mem_value > (MAX_INT >> shift) )
        return false;

    if ( shift > 0 )
        initrd_max_mem = mem_value << shift;
    else
        initrd_max_mem = mem_value;
    return true;
}

const char *skip_filename(const char *cmdline)
{
    if ( cmdline == NULL || *cmdline == '\0' )
        return cmdline;

    /* strip leading spaces, file name, then any spaces until the next 
     non-space char (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "")*/ 
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && !isspace(*cmdline) )
        cmdline++;
    while ( *cmdline != '\0' && isspace(*cmdline) )
        cmdline++;
    return cmdline;
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
