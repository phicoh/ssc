/*
dh.c

Diffie-Hellman implementation

Created:	January 2005 by Philip Homburg for NAH6
*/

#include <assert.h>
#include <stdlib.h>

#include "dh.h"
#include "../prime/isprime.h"
#include "../rndnum/rndnum.h"

/* Basic DH function. Can be used to compute both pow(g,x) and pow(g,x*y) */
void dh_gx(BigInt g, BigInt x, BigInt p, BigInt gx)
{
	bigPow(g, x, p, gx);
}

int dh_check_pq(BigInt p, BigInt q, prnd_t *prndp)
{
	if (!dh_check_q(p, q, prndp))
		return 0;

	return isPrime(p, prndp);
}

int dh_check_q(BigInt p, BigInt q, prnd_t *prndp)
{
	if (!isPrime(q, prndp))
		return 0;

	return dh_check_q_fast(p, q);
}

int dh_check_q_fast(BigInt p, BigInt q)
{
	int r;
	BigInt tmp;

	tmp= bigInit(0);
	bigSubtract(p, one, tmp);
	bigMod(tmp, q, tmp);
	r= bigCompare(tmp, zero);
	freeBignum(tmp);

	if (r != 0)
	{
		/* q does not divide p-1 */
		return 0;
	}

	return 1;
}

/* Check whether a generator is valid. The generator should be larger than
 * 1, less than p, and pow(gx,q) mod p should be equal to 1.
 */
int dh_check_gx(BigInt gx, BigInt p, BigInt q)
{
	int r;
	BigInt tmp;

	if (bigCompare(gx, one) <= 0)
	{
		/* gx should > 1 */
		return 0;
	}
	if (bigCompare(gx, p) >= 0)
	{
		/* gx should < p */
		return 0;
	}

	/* Assume that p and q have been checked */
	tmp= bigInit(0);
	bigPow(gx, q, p, tmp);
	r= bigCompare(tmp, one);
	freeBignum(tmp);

	if (r != 0)
		return 0;

	return 1;
}

/* Create a random generator that generate a group of size q. Start with a
 * random number, reduce it mod p to get a generator, eliminate subgroups
 * other than q, and check whether the result generates a group of size q.
 * This function is probablistic and may fail, but failure is very unlikely.
 */
void dh_rnd_g(BigInt p, BigInt q, prnd_t *prndp, BigInt g)
{
	int i, bits;
	BigInt n, tmp;

	n= bigInit(0);
	tmp= bigInit(0);

	bigSubtract(p, one, tmp);
	bigDivide(tmp, q, n, tmp);

	bits= bigBits(p);

	/* How many tries is reasonable? */
	for (i= 0; i<100; i++)
	{
		rndnum(prndp, bits, 1, tmp);
		if (bigCompare(tmp, p) >= 0)
		{
			/* Any g will do, a slight imbalance in the random
			 * number generator does not matter
			 */
			bigMod(tmp, p, tmp);
			assert (bigCompare(tmp, p) < 0);
		}
		bigPow(tmp, n, p, g);
		if (bigCompare(g, one) == 0)
		{
			/* g == 1 */
			continue;
		}

		bigPow(g, q, p, tmp);
		if (bigCompare(tmp, one) != 0)
		{
			/* Strange, pow(g, q) != 1 */
			continue;
		}
		freeBignum(tmp);
		return;
	}
	abort();
}

/* Generate a random number smaller than q that can be used as a DH private
 * key. Discard candidates with too many leading zero bits. This function
 * is probablistic and may fail, but failure is very unlikely.
 */
void dh_rnd_x(BigInt q, prnd_t *prndp, BigInt x)
{
	int i, bits;

	bits= bigBits(q);
	assert(bits > 1);

	/* How many tries is reasonable? */
	for (i= 0; i<100; i++)
	{
		rndnum(prndp, bits, 1, x);
		if (bigCompare(x, q) >= 0)
		{
			/* Accept a slight imbalance */
			bigMod(x, q, x);
			assert(bigCompare(x, q) < 0);
		}
		if (bigBits(x) < bits/2)
		{
			/* Strange, the high order bits are all zero. */
			continue;
		}

		/* Found one */
		return;
	}
	abort();
}

/*
 * $PchId: dh.c,v 1.2 2005/05/25 15:22:23 philip Exp $
 */
