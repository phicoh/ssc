/*
cbcmac_aes.h

Message Authentication Code based on AES in CBC mode

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../../include/os.h"
#include "../../include/rijndael.h"

#define CMA_BLOCK_SIZE	AES_BLOCKSIZE	/* 128 bits AES block size */
#define CMA_KEYSIZE	32		/* Only use 256 bit keys */

typedef struct cbcmac_aes_ctx
{
	rd_keyinstance cma_key;		/* AES key */
	u8_t cma_iv[CMA_BLOCK_SIZE];	/* Current value of the MAC */
	int cma_offset;			/* Offset in cma_block */
	u8_t cma_block[CMA_BLOCK_SIZE];	/* Partial block */
} cbcmac_aes_ctx_t;

#define CMA_DIGEST_LEN	CMA_BLOCK_SIZE	/* Length of result */

/* Initialize an hmac context */
void cbcmac_aes_init(struct cbcmac_aes_ctx *ctxp, const u8_t key[CMA_KEYSIZE]);

/* Restart. The state is reset to the start of a message */
void cbcmac_aes_reinit(struct cbcmac_aes_ctx *ctxp);

/* Add data to the current state */
void cbcmac_aes_update(struct cbcmac_aes_ctx *ctxp, const void *buf,
	size_t len);

/* Compute the mac */
void cbcmac_aes_finish(struct cbcmac_aes_ctx *ctxp,
	u8_t digest[CMA_DIGEST_LEN]);

/* Clear the context */
void cbcmac_aes_cleanup(struct cbcmac_aes_ctx *ctxp);

/*
 * $PchId: cbcmac_aes.h,v 1.1 2005/05/03 13:38:10 philip Exp $
 */
