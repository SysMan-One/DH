/*
 *++
 **********************************************************************
 *                        gost89.c                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under same license as OpenSSL     *
 *                                                                    *
 *          Implementation of GOST 28147-89 encryption algorithm      *
 *            No OpenSSL libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************
 *
 *   Modification history:
 *	31-AUG-2017	RRL	Added string.h to declare memcpy.
 *	30-NOV-2017	RRL	Added inline clause;
 *				some reformating to more readability;
 *				source level optimization of loops (see #ifdef ULONG_LONG_MAX);
 *--
 */

#include	"gost89.h"
/* Substitution blocks from RFC 4357

   Note: our implementation of gost 28147-89 algorithm
   uses S-box matrix rotated 90 degrees counterclockwise, relative to
   examples given in RFC.


*/

/* Substitution blocks from test examples for GOST R 34.11-94*/
gost_subst_block GostR3411_94_TestParamSet = {
  {0X1,0XF,0XD,0X0,0X5,0X7,0XA,0X4,0X9,0X2,0X3,0XE,0X6,0XB,0X8,0XC},
  {0XD,0XB,0X4,0X1,0X3,0XF,0X5,0X9,0X0,0XA,0XE,0X7,0X6,0X8,0X2,0XC},
  {0X4,0XB,0XA,0X0,0X7,0X2,0X1,0XD,0X3,0X6,0X8,0X5,0X9,0XC,0XF,0XE},
  {0X6,0XC,0X7,0X1,0X5,0XF,0XD,0X8,0X4,0XA,0X9,0XE,0X0,0X3,0XB,0X2},
  {0X7,0XD,0XA,0X1,0X0,0X8,0X9,0XF,0XE,0X4,0X6,0XC,0XB,0X2,0X5,0X3},
  {0X5,0X8,0X1,0XD,0XA,0X3,0X4,0X2,0XE,0XF,0XC,0X7,0X6,0X0,0X9,0XB},
  {0XE,0XB,0X4,0XC,0X6,0XD,0XF,0XA,0X2,0X3,0X8,0X1,0X0,0X7,0X5,0X9},
  {0X4,0XA,0X9,0X2,0XD,0X8,0X0,0XE,0X6,0XB,0X1,0XC,0X7,0XF,0X5,0X3}
};

/* Initialization of gost_ctx subst blocks*/
void kboxinit(gost_ctx *c, const gost_subst_block *b)
{
int	i;

	for (i = 0; i < 256; i++)
		{
		register word32 x;

		x = (b->k8[i>>4] <<4 | b->k7 [i &15])<<24;
		c->k87[i] = (x<<11 | x >> (32-11));

		x = (b->k6[i>>4] << 4 | b->k5 [i &15])<<16;
		c->k65[i] = (x<<11 | x>>(32-11));

		x = (b->k4[i>>4] <<4  | b->k3 [i &15])<<8;
		c->k43[i] = (x<<11 | x>>(32-11));

		x = b->k2[i>>4] <<4  | b->k1 [i &15];
		c->k21[i] = (x <<11 | x>> (32-11));
		}
}

/* Part of GOST 28147 algorithm moved into separate function */
inline	static word32	f(gost_ctx *c, word32 x)
{
	return c->k87[x>>24 & 255] | c->k65[x>>16 & 255]|
		c->k43[x>> 8 & 255] | c->k21[x & 255];
}


/* Low-level encryption routine - encrypts one 64 bit block*/
inline	void gostcrypt(gost_ctx *c, const byte *in, byte *out)
{
register word32 n1, n2; /* As named in the GOST */

	n1 = in[0]|(in[1]<<8)|(in[2]<<16)|(in[3]<<24);
	n2 = in[4]|(in[5]<<8)|(in[6]<<16)|(in[7]<<24);

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	out[0] = (n2&0xff);  out[1] = (n2>>8)&0xff; out[2]=(n2>>16)&0xff; out[3]=n2>>24;
	out[4] = (n1&0xff);  out[5] = (n1>>8)&0xff; out[6]=(n1>>16)&0xff; out[7]=n1>>24;
}

/* Low-level decryption routine. Decrypts one 64-bit block */
inline	void gostdecrypt(gost_ctx *c, const byte *in, byte *out)
{
register word32 n1, n2; /* As named in the GOST */

	n1 = in[0]|(in[1]<<8)|(in[2]<<16)|(in[3]<<24);
	n2 = in[4]|(in[5]<<8)|(in[6]<<16)|(in[7]<<24);

	n2 ^= f(c,n1+c->k[0]); n1 ^= f(c,n2+c->k[1]);
	n2 ^= f(c,n1+c->k[2]); n1 ^= f(c,n2+c->k[3]);
	n2 ^= f(c,n1+c->k[4]); n1 ^= f(c,n2+c->k[5]);
	n2 ^= f(c,n1+c->k[6]); n1 ^= f(c,n2+c->k[7]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	n2 ^= f(c,n1+c->k[7]); n1 ^= f(c,n2+c->k[6]);
	n2 ^= f(c,n1+c->k[5]); n1 ^= f(c,n2+c->k[4]);
	n2 ^= f(c,n1+c->k[3]); n1 ^= f(c,n2+c->k[2]);
	n2 ^= f(c,n1+c->k[1]); n1 ^= f(c,n2+c->k[0]);

	out[0] = (n2&0xff);  out[1] = (n2>>8)&0xff; out[2]=(n2>>16)&0xff; out[3]=n2>>24;
	out[4] = (n1&0xff);  out[5] = (n1>>8)&0xff; out[6]=(n1>>16)&0xff; out[7]=n1>>24;
}

/* Encrypts several full blocks in CFB mode using 8byte IV */
inline	void gost_enc_cfb(gost_ctx *ctx,const byte *iv,const byte *clear,byte *cipher, int blocks)
{
byte	cur_iv[GOST89_BLOCK_SIZE], gamma[GOST89_BLOCK_SIZE], *out;
int	i,j;
const byte *in;


#ifdef	ULONG_LONG_MAX
	/* @RRL: Try to get advantages of the 64-bit architecture */
	{
	unsigned long long *src = (unsigned long long *) iv, *dst = (unsigned long long *) &cur_iv;

	*dst = *src;
	}
#else
	for( i = 0; i < GOST89_BLOCK_SIZE; i++) cur_iv[i] = iv[i];
#endif

	for( i = 0, in = clear, out = cipher; i < blocks; i++, in += GOST89_BLOCK_SIZE, out += GOST89_BLOCK_SIZE)
		{
		gostcrypt(ctx, cur_iv, gamma);

		for (j = 0; j < GOST89_BLOCK_SIZE; j++)
			cur_iv[j] = out[j] = in[j] ^ gamma[j];
		}
}

/* Decrypts several full blocks in CFB mode using 8byte IV */
inline	void gost_dec_cfb(gost_ctx *ctx,const byte *iv,const byte *cipher,byte *clear,  int blocks)
{
byte	cur_iv[GOST89_BLOCK_SIZE], gamma[GOST89_BLOCK_SIZE], *out;
int	i,j;
const byte *in;

#ifdef	ULONG_LONG_MAX
	/* @RRL: Try to get advantages of the 64-bit architecture */
	{
	unsigned long long *src = (unsigned long long *) iv, *dst = (unsigned long long *) &cur_iv;

	*dst = *src;
	}
#else
	for( i = 0; i < GOST89_BLOCK_SIZE; i++) cur_iv[i] = iv[i];
#endif

	for( i = 0, in = cipher, out = clear; i < blocks; i++ , in += GOST89_BLOCK_SIZE ,out += GOST89_BLOCK_SIZE )
		{
		gostcrypt(ctx,cur_iv,gamma);

		for (j = 0; j < GOST89_BLOCK_SIZE; j++)
			out[j] = (cur_iv[j] = in[j]) ^ gamma[j];
		}
}

/* Set 256 bit  key into context */
inline void gost_key(gost_ctx *c, const byte *k)
{
	c->k[0]=k[ 0]|(k[ 1]<<8)|(k[ 2]<<16)|(k[ 3]<<24);
	c->k[1]=k[ 4]|(k[ 5]<<8)|(k[ 6]<<16)|(k[ 7]<<24);
	c->k[2]=k[ 8]|(k[ 9]<<8)|(k[10]<<16)|(k[11]<<24);
	c->k[3]=k[12]|(k[13]<<8)|(k[14]<<16)|(k[15]<<24);
	c->k[4]=k[16]|(k[17]<<8)|(k[18]<<16)|(k[19]<<24);
	c->k[5]=k[20]|(k[21]<<8)|(k[22]<<16)|(k[23]<<24);
	c->k[6]=k[24]|(k[25]<<8)|(k[26]<<16)|(k[27]<<24);
	c->k[7]=k[28]|(k[29]<<8)|(k[30]<<16)|(k[31]<<24);
}

/* Initalize context. Provides default value for subst_block */
inline void gost_init(gost_ctx *c, const gost_subst_block *b)
{
	if(!b)
		b = &GostR3411_94_TestParamSet;

	kboxinit(c,b);
}

/* Cleans up key from context */
inline void gost_destroy(gost_ctx *c)
{
int	i;

	for ( i = 0; i < 8; i++)
		c->k[i] = 0;
}

