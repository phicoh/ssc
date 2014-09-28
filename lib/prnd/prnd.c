/*
prnd.c

Pseudo Random Number Generator based on AES

Created:	January 2005 by Philip Homburg for NAH6
*/

#include "../../include/os.h"

#include "../../include/rijndael.h"
#include "../sha2/sha2.h"

#include "prnd.h"

/* Generate random data using an AES key and a counter stored in 
 * prndp.
 */
static void prnd_data_block(struct prnd *prndp, rd_keyinstance *keyp, 
	void *data);

void prnd_init(struct prnd *prndp, void *data, size_t len)
{
	SHA256_CTX sha_ctx;
	char seed[256];

	if (data == NULL)
	{
		/* How much data should we get from the OS? We need 256
		 * bits of random data. Assume that every byte delivers
		 * at least one bit.
		 */
		data= seed;
		len= sizeof(seed);
		os_random_data(seed, len);
	}

	/* Hash the seed */
	SHA256_Init(&sha_ctx);
	if (len)
		SHA256_Update(&sha_ctx, data, len);
	assert(PRND_KEYSIZE == SHA256_DIGEST_LENGTH);
	SHA256_Final(prndp->key, &sha_ctx);

	prndp->count_hi= 0;
	prndp->count_lo= 1;
}

void prnd_data(struct prnd *prndp, void *data, size_t len)
{
	int n, r;
	u8_t *cp;
	rd_keyinstance key;
	u8_t output[AES_BLOCKSIZE];

	r= rijndael_makekey(&key, sizeof(prndp->key), prndp->key);
	assert(r == 0);

	cp= data;
	while (len > 0)
	{
		n= AES_BLOCKSIZE;
		if (n > len)
		{
			n= len;
			prnd_data_block(prndp, &key, output);
			memcpy(cp, output, n);
		}
		else
			prnd_data_block(prndp, &key, cp);
		cp += n;
		len -= n;
	}

	/* Generate new key */
	assert(PRND_KEYSIZE == 2*AES_BLOCKSIZE);
	prnd_data_block(prndp, &key, prndp->key);
	prnd_data_block(prndp, &key, prndp->key+AES_BLOCKSIZE);
}

static void prnd_data_block(struct prnd *prndp, rd_keyinstance *keyp, 
	void *data)
{
	int r;
	u8_t input[AES_BLOCKSIZE];

	memset(input, '\0', sizeof(input));

	/* Do we want the output of the random numbers to be portable 
	 * across platforms (for example for RSA signatures)? At the moment
	 * we don't do anything special. Encrypt the counter with the AES
	 * key.
	 */
	assert(sizeof(prndp->count_lo)+sizeof(prndp->count_hi) <=
		AES_BLOCKSIZE);
	memcpy(input, &prndp->count_lo, sizeof(prndp->count_lo));
	memcpy(input+sizeof(prndp->count_lo), &prndp->count_hi,
		sizeof(prndp->count_hi));
	r= rijndael_ecb_encrypt(keyp, input, data, AES_BLOCKSIZE, NULL);
	assert(r == AES_BLOCKSIZE);

	prndp->count_lo++;
	if (prndp->count_lo == 0)
		prndp->count_hi++;
}

/*
 * $PchId: prnd.c,v 1.1 2005/05/03 10:55:44 philip Exp $
 */
