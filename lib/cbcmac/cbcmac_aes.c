/*
cbcmac_aes.c

Message Authentication Code based on AES in CBC mode

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "cbcmac_aes.h"

void cbcmac_aes_init(struct cbcmac_aes_ctx *ctxp, const u8_t key[CMA_KEYSIZE])
{
	int r;

	r= rijndael_makekey(&ctxp->cma_key, CMA_KEYSIZE, key);
	assert(r >= 0);
	memset(ctxp->cma_iv, '\0', sizeof(ctxp->cma_iv));
	ctxp->cma_offset= 0;
}

void cbcmac_aes_reinit(struct cbcmac_aes_ctx *ctxp)
{
	memset(ctxp->cma_iv, '\0', sizeof(ctxp->cma_iv));
	ctxp->cma_offset= 0;
}

void cbcmac_aes_update(struct cbcmac_aes_ctx *ctxp, const void *buf,
	size_t len)
{
	int i, j, r, offset;
	u8_t *cp, *ivp, *cma_block;
	size_t n;
	u8_t block[CMA_BLOCK_SIZE];

	cp= (u8_t *)buf;
	offset= ctxp->cma_offset;
	if (offset)
	{
		if (offset + len < CMA_BLOCK_SIZE)
		{
			memcpy(&ctxp->cma_block[offset], cp, len);
			ctxp->cma_offset= offset+len;
			return;
		}
		n= CMA_BLOCK_SIZE-offset;
		assert(n <= len);
		memcpy(&ctxp->cma_block[offset], cp, n);

		ivp= ctxp->cma_iv;
		cma_block= ctxp->cma_block;
		for (i= 0; i<CMA_BLOCK_SIZE; i++)
			block[i]= ivp[i] ^ cma_block[i];
		r= rijndael_ecb_encrypt(&ctxp->cma_key, block, ivp,
			CMA_BLOCK_SIZE, NULL);
		assert(r == CMA_BLOCK_SIZE);
		
		cp += n;
		len -= n;
		ctxp->cma_offset= offset= 0;
	}

	n= len/CMA_BLOCK_SIZE;
	ivp= ctxp->cma_iv;
	for (i= 0; i<n; i++)
	{
		for (j= 0; j<CMA_BLOCK_SIZE; j++)
			block[j]= ivp[j] ^ cp[j];
		r= rijndael_ecb_encrypt(&ctxp->cma_key, block, ivp,
			CMA_BLOCK_SIZE, NULL);
		assert(r == CMA_BLOCK_SIZE);

		cp += CMA_BLOCK_SIZE;
		len -= CMA_BLOCK_SIZE;
	}

	if (len)
	{
		assert(len < CMA_BLOCK_SIZE);
		assert(ctxp->cma_offset == 0);
		memcpy(ctxp->cma_block, cp, len);
		ctxp->cma_offset= len;
	}

}

void cbcmac_aes_finish(struct cbcmac_aes_ctx *ctxp,
	u8_t digest[CMA_DIGEST_LEN])
{
	int i, r, offset;

	offset= ctxp->cma_offset;
	assert(offset < CMA_BLOCK_SIZE);
	ctxp->cma_block[offset]= 0x80;
	for (i= offset+1; i<CMA_BLOCK_SIZE; i++)
		ctxp->cma_block[i]= '\0';
	for (i= 0; i<CMA_BLOCK_SIZE; i++)
		ctxp->cma_iv[i] ^= ctxp->cma_block[i];
	r= rijndael_ecb_encrypt(&ctxp->cma_key, ctxp->cma_iv, digest,
		CMA_BLOCK_SIZE, NULL);
	assert(r == CMA_BLOCK_SIZE);

	/* Cleanup */
	memset(ctxp->cma_iv, '\0', CMA_BLOCK_SIZE);
	memset(ctxp->cma_block, '\0', CMA_BLOCK_SIZE);
}

void cbcmac_aes_cleanup(struct cbcmac_aes_ctx *ctxp)
{
	memset(ctxp, '\0', sizeof(*ctxp));
}

/*
 * $PchId: cbcmac_aes.c,v 1.1 2005/05/03 13:38:26 philip Exp $
 */
