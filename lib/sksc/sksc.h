/* 
sksc.h

Symmetric Key Secure Channel (Based on AES-CFB and CBCMAC-AES)

Created:	December 2004 by Philip Homburg <philip@f-mnx.phicoh.com>
*/

#ifndef SKSC_H
#define SKSC_H

#include "../../include/rijndael.h"
#include "../cbcmac/cbcmac_aes.h"

#define SKSC_KEY_LENGTH	(256/8)		/* Key length in bytes */

#define SKSC_BLOCKSIZE	AES_BLOCKSIZE	/* AES blocksize */
#define SKSC_DIGEST_LEN	CMA_DIGEST_LEN

/* Overhead consists of a 128-bit AES CBCMAC.
 */
#define SKSC_OVERHEAD	(SKSC_DIGEST_LEN)

/* Note that this SKSC is simplex: full duplex connections require two secure
 * channels.
 */
typedef struct sksc
{
	u32_t message_id;

	rd_keyinstance key;
	cbcmac_aes_ctx_t mac;
} sksc_t;

/* Initialize a secure channel with a private key. */
int sksc_init(sksc_t *skscp, u8_t key[SKSC_KEY_LENGTH]);

/* Encrypt a message. The amount of output is returned or -1 (with errno set)
 * if something goes wrong.
 */
ssize_t sksc_encrypt(sksc_t *skscp, void *in, size_t inlen,
	void *out, size_t outlen);

/* Decrypt a message. The number of decoded bytes is returned or -1 (with
 * errno set if something goes wrong.
 */
ssize_t sksc_decrypt(sksc_t *skscp, void *in, size_t inlen,
	void *out, size_t outlen);

/* Clean the SKSC data structure */
void sksc_cleanup(sksc_t *skscp);

#endif /* SKSC_H */

/*
 * $PchId: sksc.h,v 1.2 2011/12/29 20:20:03 philip Exp $
 */
