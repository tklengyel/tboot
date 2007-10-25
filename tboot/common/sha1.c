/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <types.h>
#include <printk.h>
#include <sha1.h>

int SHA1_Init (SHA_CTX *c)
{
    c->h0=INIT_DATA_h0;
    c->h1=INIT_DATA_h1;
    c->h2=INIT_DATA_h2;
    c->h3=INIT_DATA_h3;
    c->h4=INIT_DATA_h4;
    c->Nl=0;
    c->Nh=0;
    c->num=0;
    return 1;
}

static void sha1_block_host_order (SHA_CTX *c, const void *d, size_t num)
{
    const SHA_LONG *W=d;
    register unsigned long A,B,C,D,E,T;
    SHA_LONG  XX[16];

    A=c->h0;
    B=c->h1;
    C=c->h2;
    D=c->h3;
    E=c->h4;

    for (;;) {
        BODY_00_15( 0,A,B,C,D,E,T,W[ 0]);
        BODY_00_15( 1,T,A,B,C,D,E,W[ 1]);
        BODY_00_15( 2,E,T,A,B,C,D,W[ 2]);
        BODY_00_15( 3,D,E,T,A,B,C,W[ 3]);
        BODY_00_15( 4,C,D,E,T,A,B,W[ 4]);
        BODY_00_15( 5,B,C,D,E,T,A,W[ 5]);
        BODY_00_15( 6,A,B,C,D,E,T,W[ 6]);
        BODY_00_15( 7,T,A,B,C,D,E,W[ 7]);
        BODY_00_15( 8,E,T,A,B,C,D,W[ 8]);
        BODY_00_15( 9,D,E,T,A,B,C,W[ 9]);
        BODY_00_15(10,C,D,E,T,A,B,W[10]);
        BODY_00_15(11,B,C,D,E,T,A,W[11]);
        BODY_00_15(12,A,B,C,D,E,T,W[12]);
        BODY_00_15(13,T,A,B,C,D,E,W[13]);
        BODY_00_15(14,E,T,A,B,C,D,W[14]);
        BODY_00_15(15,D,E,T,A,B,C,W[15]);

        BODY_16_19(16,C,D,E,T,A,B,X( 0),W[ 0],W[ 2],W[ 8],W[13]);
        BODY_16_19(17,B,C,D,E,T,A,X( 1),W[ 1],W[ 3],W[ 9],W[14]);
        BODY_16_19(18,A,B,C,D,E,T,X( 2),W[ 2],W[ 4],W[10],W[15]);
        BODY_16_19(19,T,A,B,C,D,E,X( 3),W[ 3],W[ 5],W[11],X( 0));

        BODY_20_31(20,E,T,A,B,C,D,X( 4),W[ 4],W[ 6],W[12],X( 1));
        BODY_20_31(21,D,E,T,A,B,C,X( 5),W[ 5],W[ 7],W[13],X( 2));
        BODY_20_31(22,C,D,E,T,A,B,X( 6),W[ 6],W[ 8],W[14],X( 3));
        BODY_20_31(23,B,C,D,E,T,A,X( 7),W[ 7],W[ 9],W[15],X( 4));
        BODY_20_31(24,A,B,C,D,E,T,X( 8),W[ 8],W[10],X( 0),X( 5));
        BODY_20_31(25,T,A,B,C,D,E,X( 9),W[ 9],W[11],X( 1),X( 6));
        BODY_20_31(26,E,T,A,B,C,D,X(10),W[10],W[12],X( 2),X( 7));
        BODY_20_31(27,D,E,T,A,B,C,X(11),W[11],W[13],X( 3),X( 8));
        BODY_20_31(28,C,D,E,T,A,B,X(12),W[12],W[14],X( 4),X( 9));
        BODY_20_31(29,B,C,D,E,T,A,X(13),W[13],W[15],X( 5),X(10));
        BODY_20_31(30,A,B,C,D,E,T,X(14),W[14],X( 0),X( 6),X(11));
        BODY_20_31(31,T,A,B,C,D,E,X(15),W[15],X( 1),X( 7),X(12));

        BODY_32_39(32,E,T,A,B,C,D,X( 0),X( 2),X( 8),X(13));
        BODY_32_39(33,D,E,T,A,B,C,X( 1),X( 3),X( 9),X(14));
        BODY_32_39(34,C,D,E,T,A,B,X( 2),X( 4),X(10),X(15));
        BODY_32_39(35,B,C,D,E,T,A,X( 3),X( 5),X(11),X( 0));
        BODY_32_39(36,A,B,C,D,E,T,X( 4),X( 6),X(12),X( 1));
        BODY_32_39(37,T,A,B,C,D,E,X( 5),X( 7),X(13),X( 2));
        BODY_32_39(38,E,T,A,B,C,D,X( 6),X( 8),X(14),X( 3));
        BODY_32_39(39,D,E,T,A,B,C,X( 7),X( 9),X(15),X( 4));

        BODY_40_59(40,C,D,E,T,A,B,X( 8),X(10),X( 0),X( 5));
        BODY_40_59(41,B,C,D,E,T,A,X( 9),X(11),X( 1),X( 6));
        BODY_40_59(42,A,B,C,D,E,T,X(10),X(12),X( 2),X( 7));
        BODY_40_59(43,T,A,B,C,D,E,X(11),X(13),X( 3),X( 8));
        BODY_40_59(44,E,T,A,B,C,D,X(12),X(14),X( 4),X( 9));
        BODY_40_59(45,D,E,T,A,B,C,X(13),X(15),X( 5),X(10));
        BODY_40_59(46,C,D,E,T,A,B,X(14),X( 0),X( 6),X(11));
        BODY_40_59(47,B,C,D,E,T,A,X(15),X( 1),X( 7),X(12));
        BODY_40_59(48,A,B,C,D,E,T,X( 0),X( 2),X( 8),X(13));
        BODY_40_59(49,T,A,B,C,D,E,X( 1),X( 3),X( 9),X(14));
        BODY_40_59(50,E,T,A,B,C,D,X( 2),X( 4),X(10),X(15));
        BODY_40_59(51,D,E,T,A,B,C,X( 3),X( 5),X(11),X( 0));
        BODY_40_59(52,C,D,E,T,A,B,X( 4),X( 6),X(12),X( 1));
        BODY_40_59(53,B,C,D,E,T,A,X( 5),X( 7),X(13),X( 2));
        BODY_40_59(54,A,B,C,D,E,T,X( 6),X( 8),X(14),X( 3));
        BODY_40_59(55,T,A,B,C,D,E,X( 7),X( 9),X(15),X( 4));
        BODY_40_59(56,E,T,A,B,C,D,X( 8),X(10),X( 0),X( 5));
        BODY_40_59(57,D,E,T,A,B,C,X( 9),X(11),X( 1),X( 6));
        BODY_40_59(58,C,D,E,T,A,B,X(10),X(12),X( 2),X( 7));
        BODY_40_59(59,B,C,D,E,T,A,X(11),X(13),X( 3),X( 8));

        BODY_60_79(60,A,B,C,D,E,T,X(12),X(14),X( 4),X( 9));
        BODY_60_79(61,T,A,B,C,D,E,X(13),X(15),X( 5),X(10));
        BODY_60_79(62,E,T,A,B,C,D,X(14),X( 0),X( 6),X(11));
        BODY_60_79(63,D,E,T,A,B,C,X(15),X( 1),X( 7),X(12));
        BODY_60_79(64,C,D,E,T,A,B,X( 0),X( 2),X( 8),X(13));
        BODY_60_79(65,B,C,D,E,T,A,X( 1),X( 3),X( 9),X(14));
        BODY_60_79(66,A,B,C,D,E,T,X( 2),X( 4),X(10),X(15));
        BODY_60_79(67,T,A,B,C,D,E,X( 3),X( 5),X(11),X( 0));
        BODY_60_79(68,E,T,A,B,C,D,X( 4),X( 6),X(12),X( 1));
        BODY_60_79(69,D,E,T,A,B,C,X( 5),X( 7),X(13),X( 2));
        BODY_60_79(70,C,D,E,T,A,B,X( 6),X( 8),X(14),X( 3));
        BODY_60_79(71,B,C,D,E,T,A,X( 7),X( 9),X(15),X( 4));
        BODY_60_79(72,A,B,C,D,E,T,X( 8),X(10),X( 0),X( 5));
        BODY_60_79(73,T,A,B,C,D,E,X( 9),X(11),X( 1),X( 6));
        BODY_60_79(74,E,T,A,B,C,D,X(10),X(12),X( 2),X( 7));
        BODY_60_79(75,D,E,T,A,B,C,X(11),X(13),X( 3),X( 8));
        BODY_60_79(76,C,D,E,T,A,B,X(12),X(14),X( 4),X( 9));
        BODY_60_79(77,B,C,D,E,T,A,X(13),X(15),X( 5),X(10));
        BODY_60_79(78,A,B,C,D,E,T,X(14),X( 0),X( 6),X(11));
        BODY_60_79(79,T,A,B,C,D,E,X(15),X( 1),X( 7),X(12));

        c->h0=(c->h0+E)&0xffffffffL;
        c->h1=(c->h1+T)&0xffffffffL;
        c->h2=(c->h2+A)&0xffffffffL;
        c->h3=(c->h3+B)&0xffffffffL;
        c->h4=(c->h4+C)&0xffffffffL;

        if (--num == 0) break;

        A=c->h0;
        B=c->h1;
        C=c->h2;
        D=c->h3;
        E=c->h4;

        W+=SHA_LBLOCK;
    }
}

static void sha1_block_data_order (SHA_CTX *c, const void *p, size_t num)
{
    const unsigned char *data=p;
    register unsigned long A,B,C,D,E,T,l;
    SHA_LONG  XX[16];

    A=c->h0;
    B=c->h1;
    C=c->h2;
    D=c->h3;
    E=c->h4;

    for (;;) {
        HOST_c2l(data,l); X( 0)=l;    HOST_c2l(data,l); X( 1)=l;
        BODY_00_15( 0,A,B,C,D,E,T,X( 0)); HOST_c2l(data,l); X( 2)=l;
        BODY_00_15( 1,T,A,B,C,D,E,X( 1)); HOST_c2l(data,l); X( 3)=l;
        BODY_00_15( 2,E,T,A,B,C,D,X( 2)); HOST_c2l(data,l); X( 4)=l;
        BODY_00_15( 3,D,E,T,A,B,C,X( 3)); HOST_c2l(data,l); X( 5)=l;
        BODY_00_15( 4,C,D,E,T,A,B,X( 4)); HOST_c2l(data,l); X( 6)=l;
        BODY_00_15( 5,B,C,D,E,T,A,X( 5)); HOST_c2l(data,l); X( 7)=l;
        BODY_00_15( 6,A,B,C,D,E,T,X( 6)); HOST_c2l(data,l); X( 8)=l;
        BODY_00_15( 7,T,A,B,C,D,E,X( 7)); HOST_c2l(data,l); X( 9)=l;
        BODY_00_15( 8,E,T,A,B,C,D,X( 8)); HOST_c2l(data,l); X(10)=l;
        BODY_00_15( 9,D,E,T,A,B,C,X( 9)); HOST_c2l(data,l); X(11)=l;
        BODY_00_15(10,C,D,E,T,A,B,X(10)); HOST_c2l(data,l); X(12)=l;
        BODY_00_15(11,B,C,D,E,T,A,X(11)); HOST_c2l(data,l); X(13)=l;
        BODY_00_15(12,A,B,C,D,E,T,X(12)); HOST_c2l(data,l); X(14)=l;
        BODY_00_15(13,T,A,B,C,D,E,X(13)); HOST_c2l(data,l); X(15)=l;
        BODY_00_15(14,E,T,A,B,C,D,X(14));
        BODY_00_15(15,D,E,T,A,B,C,X(15));

        BODY_16_19(16,C,D,E,T,A,B,X( 0),X( 0),X( 2),X( 8),X(13));
        BODY_16_19(17,B,C,D,E,T,A,X( 1),X( 1),X( 3),X( 9),X(14));
        BODY_16_19(18,A,B,C,D,E,T,X( 2),X( 2),X( 4),X(10),X(15));
        BODY_16_19(19,T,A,B,C,D,E,X( 3),X( 3),X( 5),X(11),X( 0));

        BODY_20_31(20,E,T,A,B,C,D,X( 4),X( 4),X( 6),X(12),X( 1));
        BODY_20_31(21,D,E,T,A,B,C,X( 5),X( 5),X( 7),X(13),X( 2));
        BODY_20_31(22,C,D,E,T,A,B,X( 6),X( 6),X( 8),X(14),X( 3));
        BODY_20_31(23,B,C,D,E,T,A,X( 7),X( 7),X( 9),X(15),X( 4));
        BODY_20_31(24,A,B,C,D,E,T,X( 8),X( 8),X(10),X( 0),X( 5));
        BODY_20_31(25,T,A,B,C,D,E,X( 9),X( 9),X(11),X( 1),X( 6));
        BODY_20_31(26,E,T,A,B,C,D,X(10),X(10),X(12),X( 2),X( 7));
        BODY_20_31(27,D,E,T,A,B,C,X(11),X(11),X(13),X( 3),X( 8));
        BODY_20_31(28,C,D,E,T,A,B,X(12),X(12),X(14),X( 4),X( 9));
        BODY_20_31(29,B,C,D,E,T,A,X(13),X(13),X(15),X( 5),X(10));
        BODY_20_31(30,A,B,C,D,E,T,X(14),X(14),X( 0),X( 6),X(11));
        BODY_20_31(31,T,A,B,C,D,E,X(15),X(15),X( 1),X( 7),X(12));

        BODY_32_39(32,E,T,A,B,C,D,X( 0),X( 2),X( 8),X(13));
        BODY_32_39(33,D,E,T,A,B,C,X( 1),X( 3),X( 9),X(14));
        BODY_32_39(34,C,D,E,T,A,B,X( 2),X( 4),X(10),X(15));
        BODY_32_39(35,B,C,D,E,T,A,X( 3),X( 5),X(11),X( 0));
        BODY_32_39(36,A,B,C,D,E,T,X( 4),X( 6),X(12),X( 1));
        BODY_32_39(37,T,A,B,C,D,E,X( 5),X( 7),X(13),X( 2));
        BODY_32_39(38,E,T,A,B,C,D,X( 6),X( 8),X(14),X( 3));
        BODY_32_39(39,D,E,T,A,B,C,X( 7),X( 9),X(15),X( 4));

        BODY_40_59(40,C,D,E,T,A,B,X( 8),X(10),X( 0),X( 5));
        BODY_40_59(41,B,C,D,E,T,A,X( 9),X(11),X( 1),X( 6));
        BODY_40_59(42,A,B,C,D,E,T,X(10),X(12),X( 2),X( 7));
        BODY_40_59(43,T,A,B,C,D,E,X(11),X(13),X( 3),X( 8));
        BODY_40_59(44,E,T,A,B,C,D,X(12),X(14),X( 4),X( 9));
        BODY_40_59(45,D,E,T,A,B,C,X(13),X(15),X( 5),X(10));
        BODY_40_59(46,C,D,E,T,A,B,X(14),X( 0),X( 6),X(11));
        BODY_40_59(47,B,C,D,E,T,A,X(15),X( 1),X( 7),X(12));
        BODY_40_59(48,A,B,C,D,E,T,X( 0),X( 2),X( 8),X(13));
        BODY_40_59(49,T,A,B,C,D,E,X( 1),X( 3),X( 9),X(14));
        BODY_40_59(50,E,T,A,B,C,D,X( 2),X( 4),X(10),X(15));
        BODY_40_59(51,D,E,T,A,B,C,X( 3),X( 5),X(11),X( 0));
        BODY_40_59(52,C,D,E,T,A,B,X( 4),X( 6),X(12),X( 1));
        BODY_40_59(53,B,C,D,E,T,A,X( 5),X( 7),X(13),X( 2));
        BODY_40_59(54,A,B,C,D,E,T,X( 6),X( 8),X(14),X( 3));
        BODY_40_59(55,T,A,B,C,D,E,X( 7),X( 9),X(15),X( 4));
        BODY_40_59(56,E,T,A,B,C,D,X( 8),X(10),X( 0),X( 5));
        BODY_40_59(57,D,E,T,A,B,C,X( 9),X(11),X( 1),X( 6));
        BODY_40_59(58,C,D,E,T,A,B,X(10),X(12),X( 2),X( 7));
        BODY_40_59(59,B,C,D,E,T,A,X(11),X(13),X( 3),X( 8));

        BODY_60_79(60,A,B,C,D,E,T,X(12),X(14),X( 4),X( 9));
        BODY_60_79(61,T,A,B,C,D,E,X(13),X(15),X( 5),X(10));
        BODY_60_79(62,E,T,A,B,C,D,X(14),X( 0),X( 6),X(11));
        BODY_60_79(63,D,E,T,A,B,C,X(15),X( 1),X( 7),X(12));
        BODY_60_79(64,C,D,E,T,A,B,X( 0),X( 2),X( 8),X(13));
        BODY_60_79(65,B,C,D,E,T,A,X( 1),X( 3),X( 9),X(14));
        BODY_60_79(66,A,B,C,D,E,T,X( 2),X( 4),X(10),X(15));
        BODY_60_79(67,T,A,B,C,D,E,X( 3),X( 5),X(11),X( 0));
        BODY_60_79(68,E,T,A,B,C,D,X( 4),X( 6),X(12),X( 1));
        BODY_60_79(69,D,E,T,A,B,C,X( 5),X( 7),X(13),X( 2));
        BODY_60_79(70,C,D,E,T,A,B,X( 6),X( 8),X(14),X( 3));
        BODY_60_79(71,B,C,D,E,T,A,X( 7),X( 9),X(15),X( 4));
        BODY_60_79(72,A,B,C,D,E,T,X( 8),X(10),X( 0),X( 5));
        BODY_60_79(73,T,A,B,C,D,E,X( 9),X(11),X( 1),X( 6));
        BODY_60_79(74,E,T,A,B,C,D,X(10),X(12),X( 2),X( 7));
        BODY_60_79(75,D,E,T,A,B,C,X(11),X(13),X( 3),X( 8));
        BODY_60_79(76,C,D,E,T,A,B,X(12),X(14),X( 4),X( 9));
        BODY_60_79(77,B,C,D,E,T,A,X(13),X(15),X( 5),X(10));
        BODY_60_79(78,A,B,C,D,E,T,X(14),X( 0),X( 6),X(11));
        BODY_60_79(79,T,A,B,C,D,E,X(15),X( 1),X( 7),X(12));

        c->h0=(c->h0+E)&0xffffffffL;
        c->h1=(c->h1+T)&0xffffffffL;
        c->h2=(c->h2+A)&0xffffffffL;
        c->h3=(c->h3+B)&0xffffffffL;
        c->h4=(c->h4+C)&0xffffffffL;

        if (--num == 0) break;

        A=c->h0;
        B=c->h1;
        C=c->h2;
        D=c->h3;
        E=c->h4;
    }
}

int SHA1_Update (SHA_CTX *c, const void *data_, size_t len)
{
    const unsigned char *data=data_;
    register SHA_LONG * p;
    register SHA_LONG l;
    size_t sw,sc,ew,ec;

    if (len==0) return 1;

    l=(c->Nl+(((SHA_LONG)len)<<3))&0xffffffffUL;
    if (l < c->Nl) /* overflow */
        c->Nh++;
    c->Nh+=(len>>29); /* might cause compiler warning on 16-bit */
    c->Nl=l;

    if (c->num != 0) {
        p=c->data;
        sw=c->num>>2;
        sc=c->num&0x03;

        if ((c->num+len) >= SHA_CBLOCK) {
            l=p[sw]; HOST_p_c2l(data,l,sc); p[sw++]=l;
            for (; sw<SHA_LBLOCK; sw++) {
                HOST_c2l(data,l); p[sw]=l;
            }
            sha1_block_host_order (c,p,1);
            len-=(SHA_CBLOCK-c->num);
            c->num=0;
            /* drop through and do the rest */
        }
        else {
            c->num+=(unsigned int)len;
            if ((sc+len) < 4) {/* ugly, add char's to a word */
                l=p[sw]; HOST_p_c2l_p(data,l,sc,len); p[sw]=l;
            }
            else {
                ew=(c->num>>2);
                ec=(c->num&0x03);
                if (sc)
                    l=p[sw];
                HOST_p_c2l(data,l,sc);
                p[sw++]=l;
                for (; sw < ew; sw++) {
                    HOST_c2l(data,l); p[sw]=l;
                }
                if (ec) {
                    HOST_c2l_p(data,l,ec); p[sw]=l;
                }
            }
            return 1;
        }
    }

    sw=len/SHA_CBLOCK;
    if (sw > 0) {
        sha1_block_data_order(c,data,sw);
        sw*=SHA_CBLOCK;
        data+=sw;
        len-=sw;
    }

    if (len!=0) {
        p = c->data;
        c->num = len;
        ew=len>>2;  /* words to copy */
        ec=len&0x03;
        for (; ew; ew--,p++) {
            HOST_c2l(data,l); *p=l;
        }
        HOST_c2l_p(data,l,ec);
        *p=l;
    }
    return 1;
}

int SHA1_Final (unsigned char *md, SHA_CTX *c)
{
    register SHA_LONG *p;
    register unsigned long l;
    register int i,j;
    static const unsigned char end[4]={0x80,0x00,0x00,0x00};
    const unsigned char *cp=end;

    /* c->num should definitly have room for at least one more byte. */
    p=c->data;
    i=c->num>>2;
    j=c->num&0x03;

    l = (j==0) ? 0 : p[i];
    HOST_p_c2l(cp,l,j); p[i++]=l; /* i is the next 'undefined word' */

    /* save room for Nl and Nh */
    if (i>(SHA_LBLOCK-2)) {
        if (i<SHA_LBLOCK) p[i]=0;
        sha1_block_host_order (c,p,1);
        i=0;
    }
    for (; i<(SHA_LBLOCK-2); i++)
        p[i]=0;

    p[SHA_LBLOCK-2]=c->Nh;
    p[SHA_LBLOCK-1]=c->Nl;

    sha1_block_host_order (c,p,1);

    HASH_MAKE_STRING(c,md);

    c->num=0;
    /* clear stuff, HASH_BLOCK may be leaving some stuff on the stack
     * but I'm not worried :-)
    OPENSSL_cleanse((void *)c,sizeof(SHA_CTX));
     */
    return 1;
}

int sha1_buffer(const unsigned char* buffer, size_t len, unsigned char md[SHA_DIGEST_LENGTH])
{
    SHA_CTX c;

    if (md == NULL)
        return 1;
    if (!SHA1_Init(&c))
        return 1;
    SHA1_Update(&c,buffer,len);
    SHA1_Final(md,&c);
    return 0;
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
