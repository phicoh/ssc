/*
isprime.c

Check whether a BigInt is likely to be a prime number or not

Created:	January 2005 by Philip Homburg for NAH6
*/

#include <assert.h>
#include <stdlib.h>

#include "isprime.h"
#include "../rndnum/rndnum.h"

#define N_PRIMES	1000
unsigned long smallprimes[N_PRIMES];

/* Fill the array smallprimes with the first N_PRIMES primes */
static void build_small_primes_list(void);

/* Perform the Rabin-Miller primality test. Return 0 if the value is
 * not a prime, return 1 of the number is likely to be prime.
 */
static int isPrime_RabinMiller(BigInt n, prnd_t *prndp);

int isPrime(BigInt bi, prnd_t *prndp)
{
	static int first_time= 1;

	int i;
	BigInt sp, res;

	if (first_time)
	{
		build_small_primes_list();
		first_time= 0;
	}

	/* Make sure that bi is not smaller than 2 */
	if (bigCompare(bi, two) < 0)
		return 0;

	sp= bigInit(0);
	res= bigInit(0);

	/* Try the small primes */
	for (i= 0; i<N_PRIMES; i++)
	{
		reset_big(sp, smallprimes[i]);

		bigMod(bi, sp, res);
		if (bigCompare(res, zero) == 0)
		{
			/* We may be dealing with a small prime */
			if (bigCompare(bi, sp) == 0)
			{
				freeBignum(sp);
				freeBignum(res);
				return 1;
			}
			break;
		}
	}
	freeBignum(sp);
	freeBignum(res);

	if (i != N_PRIMES)
		return 0;

	return isPrime_RabinMiller(bi, prndp);
}

static void build_small_primes_list(void)
{
	int i, j;
	unsigned long n;

	i= 0;

	for (n= 2; n < 0xffffffff; n++)
	{
		for (j= 0; j<i; j++)
		{
			if (n % smallprimes[j] == 0)
				break;
		}
		if (j == i)
		{
			assert(i < N_PRIMES);
			smallprimes[i]= n;
			i++;
			if (i == N_PRIMES)
				return;
		}
	}

	/* Strange */
	abort();
}

static int isPrime_RabinMiller(BigInt n, prnd_t *prndp)
{
	/* Rabin-Miller test from "Practical Cryptography" (Ferguson and
	 * Schneier)
	 */
	int i, k;
	unsigned long t, bits;
	BigInt a, n_1, s, v;

	/* Verify the candidate is odd and larger than two. */
	if (!ODD(n) || bigCompare(n, two) <= 0)
		return 0;

	a= bigInit(0);
	n_1= bigInit(0);
	s= bigInit(0);
	v= bigInit(0);

	/* Compute s and t such that pow(2,t)*s == n-1 */
	bigSubtract(n, one, n_1);
	bigCopy(n_1, s);
	t= 0;
	while (EVEN(s))
	{
		bigRightShift(s, 1, s);
		t++;
	}

	bits= bigBits(n);

	/* Reduce the uncertainty below one in pow(2,128). Every iteration
	 * gets another factor of four.
	 */
	for (k= 0; k<128; k += 2)
	{
		for (i= 0; i<10; i++)
		{
			/* We need a random number a such that 2 <= a <= n-1.
			 * Maybe we should use a function that generates those
			 * numbers directly.
			 */
			rndnum(prndp, bits, 0, a);
			if (bigCompare(a, n) >= 0)
			{
				/* Reducing a modulo n creates a slight
				 * imbalance in the distriution of a. This
				 * should be no problem.
			 	 */
				bigMod(a, n, a);
			}
			if (bigCompare(a, two) >= 0)
				break;
		}
		assert(bigCompare(a, n) < 0);
		assert(bigCompare(a, two) >= 0);

		bigPow(a, s, n, v);
		if (bigCompare(v, one) == 0)
		{
			/* Passed test */
			continue;
		}

		assert(t > 0);
		for (i= 0; i < t; i++)
		{
			if (bigCompare(v, n_1) == 0)
			{
				/* Okay, passed test */
				break;
			}

			/* Square v */
			bigPow(v, two, n, v);
		}

		if (i == t)
		{
			/* Test failed, not prime */
			freeBignum(a);
			freeBignum(n_1);
			freeBignum(s);
			freeBignum(v);
			return 0;
		}
		
		/* Passed test, try another one */
	}

	freeBignum(a);
	freeBignum(n_1);
	freeBignum(s);
	freeBignum(v);

	return 1;
}

/*
 * $PchId: isprime.c,v 1.1 2005/05/03 10:32:40 philip Exp $
 */
