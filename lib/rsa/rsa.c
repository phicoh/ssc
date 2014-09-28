/*
rsa.c

RSA signatures, key generation

Created:	January 2005 by Philip Homburg
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "../../include/rijndael.h"

#include "rsa.h"
#include "../prime/rndprime.h"
#include "../sha2/sha2.h"

/* Use the Chinese remainder theorem to compute pow(m,d) mod p*q */
static void rsa_pow(BigInt m, BigInt d, BigInt p, BigInt q, BigInt s);

/* The extended greated common divisor algorithm. This used to compute
 * the inverse of a modulo b.
 */
static void egcd(BigInt a, BigInt b, BigInt gcd, BigInt u);

/* Reduce a modulo m */
static void Mod(BigInt a, BigInt m, BigInt r);

/* Expand a hash value to the full range of a modulus n */
static void fdh_mgf1(void *hash, size_t size, BigInt n, BigInt m);

void rsa_rnd_key(int bits, prnd_t *prndp, BigInt n, BigInt p)
{
	BigInt q;

	rnd_rsa_prime(bits/2, prndp, p);
	q= bigInit(0);
	rnd_rsa_prime(bits/2, prndp, q);
	bigMultiply(p, q, n);
	freeBignum(q);
}

void rsa_sign(unsigned char hash[RSA_HASH_LEN], BigInt n, BigInt p, BigInt s)
{
	int r;
	BigInt d, e, m, q, t, tmp1, tmp2;

	d= bigInit(0);
	e= bigInit(RSA_PUBEXP_SIGN);	/* The public exponent for signing */
	q= bigInit(0);
	m= bigInit(0);
	t= bigInit(0);
	tmp1= bigInit(0);
	tmp2= bigInit(0);

	/* Expand the hash value to the full domain of the RSA public key */
	fdh_mgf1(hash, RSA_HASH_LEN, n, m);

	/* Compute q */
	bigDivide(n, p, q, tmp1);
	if (bigCompare(tmp1, zero) != 0)
		goto fail;

	/* Compute t as (p-1)*(q-1). Leave out the lcm part. */
	bigSubtract(p, one, tmp1);
	bigSubtract(q, one, tmp2);
	bigMultiply(tmp1, tmp2, t);

	/* Compute the inverse of the public exponent */
	egcd(e, t, tmp1, d);
	if (bigCompare(tmp1, one) != 0)
		goto fail;
	Mod(d, t, d);

	/* Sign m */
	rsa_pow(m, d, p, q, s);

	r= rsa_verify(hash, s, n);
	if (!r)
		goto fail;

	freeBignum(d);
	freeBignum(e);
	freeBignum(m);
	freeBignum(q);
	freeBignum(t);
	freeBignum(tmp1);
	freeBignum(tmp2);
	return;

fail:
	freeBignum(d);
	freeBignum(e);
	freeBignum(m);
	freeBignum(q);
	freeBignum(t);
	freeBignum(tmp1);
	freeBignum(tmp2);

	/* Something went wrong. Just return a bad value */
	reset_big(s, 0);
	return;
}

int rsa_verify(unsigned char hash[RSA_HASH_LEN], BigInt s, BigInt n)
{
	int r;
	BigInt e, m, ms;

	e= bigInit(RSA_PUBEXP_SIGN);	/* The public exponent for signing */
	m= bigInit(0);
	ms= bigInit(0);

	fdh_mgf1(hash, RSA_HASH_LEN, n, m);

	bigPow(s, e, n, ms);

	r= (bigCompare(m, ms) == 0);

	if (bigCompare(m, zero) == 0)
	{
		/* Something went wrong in fdh */
		r= 0;
	}

	freeBignum(e);
	freeBignum(m);
	freeBignum(ms);

	return r;
}

static void rsa_pow(BigInt m, BigInt d, BigInt p, BigInt q, BigInt s)
{
	BigInt d1, m1, p1, sp, sq, q_inv, tmp1, tmp2;

	d1= bigInit(0);
	m1= bigInit(0);
	p1= bigInit(0);
	sp= bigInit(0);
	sq= bigInit(0);
	q_inv= bigInit(0);
	tmp1= bigInit(0);
	tmp2= bigInit(0);

	/* Use the Chinese remainder theorem to compute pow(m,d) mod p*q */
	bigMod(m, p, m1);
	bigSubtract(p, one, p1);
	bigMod(d, p1, d1);
	bigPow(m1, d1, p, sp);	/* pow(m, d) mod p */

	bigMod(m, q, m1);
	bigSubtract(q, one, p1);
	bigMod(d, p1, d1);
	bigPow(m1, d1, q, sq);	/* pow(m, d) mod q */

	/* Compute the inverse of q modulo p. */
	egcd(q, p, tmp1, q_inv);
	Mod(q_inv, p, q_inv);

	/* Combine sp and sq */
	bigSubtract(sp, sq, tmp1);	/* sp-sq */
	Mod(tmp1, p, tmp1);		/* (sp-sq) mod p */
	bigMultiply(tmp1, q_inv, tmp2);
	bigMod(tmp2, p, tmp2);	 	/* (sp-sq)/q mod p */
	bigMultiply(tmp2, q, tmp1);	/* ((sp-sq)/q mod p)*q */
	bigAdd(tmp1, sq, s);		/* ((sp-sq)/q mod p)*q+sq */

	freeBignum(d1);
	freeBignum(m1);
	freeBignum(p1);
	freeBignum(sp);
	freeBignum(sq);
	freeBignum(q_inv);
	freeBignum(tmp1);
	freeBignum(tmp2);
}

static void egcd(BigInt a, BigInt b, BigInt gcd, BigInt u)
{
	BigInt c, d, nc, q, uc, ud, nuc, tmp;

	c= bigInit(0);
	d= bigInit(0);
	nc= bigInit(0);
	q= bigInit(0);
	uc= bigInit(1);
	ud= bigInit(0);
	nuc= bigInit(0);
	tmp= bigInit(0);

	bigCopy(a, c);
	bigCopy(b, d);

	while(bigCompare(c, zero) != 0)
	{
		bigDivide(d, c, q, nc);
		bigCopy(c, d);
		bigCopy(nc, c);
		bigMultiply(uc, q, tmp);
		bigSubtract(ud, tmp, nuc);
		bigCopy(uc, ud);
		bigCopy(nuc, uc);
	}

	bigCopy(d, gcd);
	bigCopy(ud, u);

	freeBignum(c);
	freeBignum(d);
	freeBignum(nc);
	freeBignum(q);
	freeBignum(uc);
	freeBignum(ud);
	freeBignum(nuc);
	freeBignum(tmp);
}

static void Mod(BigInt a, BigInt m, BigInt r)
{
	assert(bigCompare(m, zero) > 0);

	bigMod(a, m, r);

	if (bigCompareX(r, zero) < 0)
	{
		/* bigMod doesn't work properly for negative values */
		bigAdd(r, m, r);
		assert(bigCompareX(r, zero) >= 0);
	}
}

/* Generate a full domain hash using the MGF1 function from KPCS #1 version
 * 2.1.
 *
 * Generate an integral number of blocks that is at least as large as the
 * modulus. The generated data is interpreted as a BigInt stored in big-endian
 * format. Reduce the resulting number modulo n. Return 0 if something goes
 * wrong. Note: rsa_verify should reject the value zero as invalid.
 */
static void fdh_mgf1(void *hash, size_t size, BigInt n, BigInt m)
{
	int i;
	unsigned bits, bytes, blocks;
	u8_t *buf;
	u8_t counter[4];
	SHA256_CTX ctx, tmp_ctx;

	bits= bigBits(n);
	bytes= (bits+7)/8;
	blocks= (bytes + SHA256_DIGEST_LENGTH-1)/SHA256_DIGEST_LENGTH;
	assert(blocks < 255);

	buf= malloc(blocks*SHA256_DIGEST_LENGTH);
	if (buf == NULL)
		goto fail;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, size);

	memset(counter, '\0', sizeof(counter));
	for (i= 0; i<blocks; i++)
	{
		counter[sizeof(counter)-1]= i+1;
		tmp_ctx= ctx;
		SHA256_Update(&tmp_ctx, counter, sizeof(counter));
		SHA256_Final(&buf[i*SHA256_DIGEST_LENGTH], &tmp_ctx);
	}

	bufToBig_be(buf, blocks*SHA256_DIGEST_LENGTH, m);

	free(buf); buf= NULL;

	bigMod(m, n, m);
	assert(bigCompare(m, n) < 0);

	return;

fail:
	reset_big(m, 0);
}

/*
 * $PchId: rsa.c,v 1.1 2005/05/02 15:11:06 philip Exp $
 */
