/*
prnd.h

Pseudo Random Number Generator based on AES

Created:	January 2005 by Philip Homburg for NAH6
*/

#ifndef PRND__H
#define PRND__H

#include "../../include/os.h"

/* This value of PRND_KEYSIZE happens to be the output size of SHA-256,
 * a valid key size for AES and two times the block size of AES.
 */
#define PRND_KEYSIZE	32

typedef struct prnd
{
	u8_t key[PRND_KEYSIZE];
	u32_t count_hi;
	u32_t count_lo;
} prnd_t;

/* Initialize a pseudo random number generator. If data is equal to a
 * nul pointer, the random number generator of the underlying operating
 * system is used to obtain a seed. Otherwise, len specifies the amount
 * of data in the buffer pointed to by data that is to be used as seed.
 */
void prnd_init(struct prnd *prndp, void *data, size_t len);

/* Fill a block with length len and pointed to by data with the output of
 * a pseudo random number generator. prndp should be initialized with 
 * prnd_init before calling this function.
 */
void prnd_data(struct prnd *prndp, void *data, size_t len);

#endif /* PRND__H */

/*
 * $PchId: prnd.h,v 1.2 2011/12/28 11:47:28 philip Exp $
 */
