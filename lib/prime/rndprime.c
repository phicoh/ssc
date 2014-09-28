/*
rndprime.c

Generate random prime numbers

Created:	January 2005 by Philip Homburg for NAH6
*/

#include <assert.h>
#include <stdlib.h>

#include "rndprime.h"
#include "isprime.h"
#include "../rndnum/rndnum.h"

void rnd_prime(int bits, prnd_t *prndp, BigInt p)
{
	int i;

	for (i= 0; i<100*bits; i++)
	{
		rndnum(prndp, bits, 1, p);

		if (isPrime(p, prndp))
			return;
	}

	abort();
}

void rnd_sg_prime(int bits, BigInt q, prnd_t *prndp, BigInt p)
{
	int i, sg_bits, extra_bits, p_bits;
	BigInt m, tmp;

	sg_bits= bigBits(q);
	assert(bits >= sg_bits);
	extra_bits= bits-sg_bits+1;

	m= bigInit(0);
	tmp= bigInit(0);

	for (i= 0; i<100*bits; i++)
	{
		rndnum(prndp, extra_bits, 1, m);

		bigMultiply(q, m, tmp);
		bigAdd(tmp, one, p);

		p_bits= bigBits(p);
		if (p_bits != bits)
		{
			assert(p_bits == bits+1);

			/* Try again with m/2 */
			bigRightShift(m, 1, m);
			bigMultiply(q, m, tmp);
			bigAdd(tmp, one, p);
			p_bits= bigBits(p);

			if (p_bits != bits)
				abort();
		}

		if (isPrime(p, prndp))
		{
			freeBignum(m);
			freeBignum(tmp);

			return;
		}
	}

	abort();
}

void rnd_rsa_prime(int bits, prnd_t *prndp, BigInt p)
{
	int i;
	BigInt three, five, tmp;

	three= bigInit(3);
	five= bigInit(5);
	tmp= bigInit(0);
	for (i= 0; i<100*bits; i++)
	{
		rndnum(prndp, bits, 1, p);

		bigMod(p, three, tmp);
		if (bigCompare(tmp, one) == 0)
			continue;
		bigMod(p, five, tmp);
		if (bigCompare(tmp, one) == 0)
			continue;

		if (isPrime(p, prndp))
		{
			freeBignum(three);
			freeBignum(five);
			freeBignum(tmp);
			return;
		}
	}

	abort();
}


/*
 * $PchId: rndprime.c,v 1.1 2005/05/03 10:35:27 philip Exp $
 */
