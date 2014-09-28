/*
rndnum.c

Generate an n bit random number and return it as a BigInt

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../../include/os.h"

#include "rndnum.h"

void rndnum(prnd_t *prndp, int bits, int setmsb, BigInt v)
{
	int bytes, extra_bits;
	unsigned mask, msb;
	u8_t *buf;

	assert(bits > 0);

	bytes= (bits+7)/8;

	extra_bits= bytes*8-bits;

	mask= (~(0xff << (8-extra_bits)) & 0xff);
	msb= (1 << (7-extra_bits));

	buf= os_malloc("rndnum", bytes);
	assert(buf);

	prnd_data(prndp, buf, bytes);
	buf[bytes-1] &= mask;
	if (setmsb)
		buf[bytes-1] |= msb;
	bufToBig(buf, bytes, v);

	os_free(buf); buf= NULL;
}

/*
 * $PchId: rndnum.c,v 1.1 2005/05/03 10:02:57 philip Exp $
 */
