/*
isprime.h

Check whether a BigInt is likely to be a prime number or not

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../mp/libcrypt.h"
#include "../prnd/prnd.h"

/* Check whether is number is prime. This function returns 0 if the number is
 * not a prime number. If the number is likely to be a prime, the value 1
 * is returned. prndp should point to an initialized pseudo random number
 * generator.
 */
int isPrime(BigInt bi, prnd_t *prndp);

/*
 * $PchId: isprime.h,v 1.1 2005/05/03 10:31:38 philip Exp $
 */
