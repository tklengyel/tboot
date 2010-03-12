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

#ifndef __SHA1_H__
#define __SHA1_H__

#define SHA_LONG unsigned long
#define SHA_LBLOCK  16
#define SHA_CBLOCK  (SHA_LBLOCK*4)  /* SHA treats input data as a
                                     * contiguous array of 32 bit
                                     * wide big-endian values.*/
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
#define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st
  {
  SHA_LONG h0,h1,h2,h3,h4;
  SHA_LONG Nl,Nh;
  SHA_LONG data[SHA_LBLOCK];
  unsigned int num;
  } SHA_CTX;

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);

#define INIT_DATA_h0 0x67452301UL
#define INIT_DATA_h1 0xefcdab89UL
#define INIT_DATA_h2 0x98badcfeUL
#define INIT_DATA_h3 0x10325476UL
#define INIT_DATA_h4 0xc3d2e1f0UL

# define Xupdate(a,ix,ia,ib,ic,id)  ( (a)=(ia^ib^ic^id),  \
            ix=(a)=ROTATE((a),1)  \
          )
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#define HOST_c2l(c,l) (l =(((unsigned long)(*((c)++)))<<24),    \
       l|=(((unsigned long)(*((c)++)))<<16),    \
       l|=(((unsigned long)(*((c)++)))<< 8),    \
       l|=(((unsigned long)(*((c)++)))    ),    \
       l)
#define HOST_p_c2l(c,l,n) {         \
      switch (n) {          \
      case 0: l =((unsigned long)(*((c)++)))<<24; \
      case 1: l|=((unsigned long)(*((c)++)))<<16; \
      case 2: l|=((unsigned long)(*((c)++)))<< 8; \
      case 3: l|=((unsigned long)(*((c)++)));   \
        } }
#define HOST_p_c2l_p(c,l,sc,len) {          \
      switch (sc) {         \
      case 0: l =((unsigned long)(*((c)++)))<<24; \
        if (--len == 0) break;      \
      case 1: l|=((unsigned long)(*((c)++)))<<16; \
        if (--len == 0) break;      \
      case 2: l|=((unsigned long)(*((c)++)))<< 8; \
        } }
/* NOTE the pointer is not incremented at the end of this */
#define HOST_c2l_p(c,l,n) {         \
      l=0; (c)+=n;          \
      switch (n) {          \
      case 3: l =((unsigned long)(*(--(c))))<< 8; \
      case 2: l|=((unsigned long)(*(--(c))))<<16; \
      case 1: l|=((unsigned long)(*(--(c))))<<24; \
        } }
#define HOST_l2c(l,c) (*((c)++)=(unsigned char)(((l)>>24)&0xff),  \
       *((c)++)=(unsigned char)(((l)>>16)&0xff),  \
       *((c)++)=(unsigned char)(((l)>> 8)&0xff),  \
       *((c)++)=(unsigned char)(((l)    )&0xff),  \
       l)

#define HASH_MAKE_STRING(c,s)   do {  \
  unsigned long ll;   \
  ll=(c)->h0; HOST_l2c(ll,(s)); \
  ll=(c)->h1; HOST_l2c(ll,(s)); \
  ll=(c)->h2; HOST_l2c(ll,(s)); \
  ll=(c)->h3; HOST_l2c(ll,(s)); \
  ll=(c)->h4; HOST_l2c(ll,(s)); \
  } while (0)

#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

#define F_00_19(b,c,d)  ((((c) ^ (d)) & (b)) ^ (d))
#define F_20_39(b,c,d)  ((b) ^ (c) ^ (d))
#define F_40_59(b,c,d)  (((b) & (c)) | (((b)|(c)) & (d)))
#define F_60_79(b,c,d)  F_20_39(b,c,d)

#define BODY_00_15(i,a,b,c,d,e,f,xi) \
  (f)=xi+(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define BODY_16_19(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
  Xupdate(f,xi,xa,xb,xc,xd); \
  (f)+=(e)+K_00_19+ROTATE((a),5)+F_00_19((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define BODY_20_31(i,a,b,c,d,e,f,xi,xa,xb,xc,xd) \
  Xupdate(f,xi,xa,xb,xc,xd); \
  (f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define BODY_32_39(i,a,b,c,d,e,f,xa,xb,xc,xd) \
  Xupdate(f,xa,xa,xb,xc,xd); \
  (f)+=(e)+K_20_39+ROTATE((a),5)+F_20_39((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define BODY_40_59(i,a,b,c,d,e,f,xa,xb,xc,xd) \
  Xupdate(f,xa,xa,xb,xc,xd); \
  (f)+=(e)+K_40_59+ROTATE((a),5)+F_40_59((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define BODY_60_79(i,a,b,c,d,e,f,xa,xb,xc,xd) \
  Xupdate(f,xa,xa,xb,xc,xd); \
  (f)=xa+(e)+K_60_79+ROTATE((a),5)+F_60_79((b),(c),(d)); \
  (b)=ROTATE((b),30);

#define X(i) XX[i]
#define BUFSIZE 1024*16

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);

/*
    int sha1_file(const char* path, unsigned char md[SHA_DIGEST_LENGTH]);
*/
int sha1_buffer(const unsigned char* buffer, size_t len, unsigned char md[SHA_DIGEST_LENGTH]);

#endif /* __SHA1_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

