/*
rndnum.h

Generate an n bit random number and return it as a BigInt

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../mp/libcrypt.h"
#include "../prnd/prnd.h"

/* Generate a random number with size bits. If setmsb is non-zero,
 * the highest bit of the random number will be set to one. prndp should
 * point to an initialized pseudo random number generator. The random
 * number will be returned in v, which has to be initialized before calling
 * this function.
 */
void rndnum(prnd_t *prndp,  int bits, int setmsb, BigInt v);

/*
 * $PchId: rndnum.h,v 1.1 2005/05/03 10:02:40 philip Exp $
 */
