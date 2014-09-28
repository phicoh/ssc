/*
rndprime.h

Generate random prime numbers

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../mp/libcrypt.h"
#include "../prnd/prnd.h"

/* Generate a random prime number with the size specified by bits. prndp
 * should point to an initialized pseudo random number generator. p
 * receives the resulting prime and should be initialized before calling
 * this function.
 */
void rnd_prime(int bits, prnd_t *prndp, BigInt p);

/* Generate a random prime number with the additional constrait that q
 * divides p minus one. (This is useful for Diffie-Hellman computations in
 * a subgroup. Otherwise, this function is the same as rnd_prime.
 */
void rnd_sg_prime(int bits, BigInt q, prnd_t *prndp, BigInt p);

/* Generate a random prime such that p minus one is relative prime to
 * 3 and 5. This is suitable for (our use of) RSA. Otherwise this function
 * is the same as rnd_prime.
 */
void rnd_rsa_prime(int bits, prnd_t *prndp, BigInt p);

/*
 * $PchId: rndprime.h,v 1.1 2005/05/03 10:33:39 philip Exp $
 */
