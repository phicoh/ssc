/* 
sksc.c

Symmetric Key Secure Channel (Based on AES-CFB and CBCMAC-AES)

Created:	December 2004 by Philip Homburg <philip@f-mnx.phicoh.com>
*/

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "sksc.h"

/* For encryption, the output buffer has to be at least MIN_SIZE bigger
 * than the plaintext.
 */
#define MIN_SIZE	(SKSC_DIGEST_LEN)	

/* Data structure for encryption. This structure contains the key,
 * a pointer in the output buffer, (optionally) a partial plain text block,
 * and the current initialisation vector.
 */
struct cfb_enc_env
{
	rd_keyinstance *keyp;
	u8_t *outp;
	u8_t block[SKSC_BLOCKSIZE];
	int offset;
	u8_t iv[SKSC_BLOCKSIZE];
};

/* This is the datastructure for decryption. */
struct cfb_dec_env
{
	rd_keyinstance *keyp;
	u8_t *inp;
	size_t insize;
	u8_t block[SKSC_BLOCKSIZE];
	int offset;
	u8_t iv[SKSC_BLOCKSIZE];
};

/* Add data to be encrypted */
static void cfb_enc_update(struct cfb_enc_env *envp, void *data, size_t size);

/* Flush the last block */
static void cfb_enc_finish(struct cfb_enc_env *envp);

/* Get decrypted data */
static void cfb_dec_extract(struct cfb_dec_env *envp, void *data, size_t size);

#ifdef SKSC_INSECURE_DEBUGING
static void sys_printblock(char *label, void *data, size_t size);
#endif

int sksc_init(sksc_t *skscp, u8_t key[SKSC_KEY_LENGTH])
{
	int r;

#ifdef SKSC_INSECURE_DEBUGING
	sys_printblock("key: ", key, SKSC_KEY_LENGTH);
#endif
	assert(CMA_KEYSIZE == SKSC_KEY_LENGTH);

	cbcmac_aes_init(&skscp->mac, key);

	r= rijndael_makekey(&skscp->key, SKSC_KEY_LENGTH, key);
	if (r < 0)
	{
		errno= EINVAL;
		return -1;
	}

	skscp->message_id= 0;

	return 0;
}

ssize_t sksc_encrypt(sksc_t *skscp, void *in, size_t inlen,
	void *out, size_t outlen)
{
	size_t totlen;
	u32_t mid;
	u8_t *cp;
	u8_t mac[CMA_DIGEST_LEN];
	u8_t midstr[8];
	struct cfb_enc_env env;

	totlen= MIN_SIZE + inlen;

	/* Verify request size */
	assert(totlen > inlen);
	if (totlen > outlen)
	{
		errno= EINVAL;
		return -1;
	}

	/* Marshal message ID for HMAC. Assume 32-bit limits for now */
	mid= skscp->message_id;
	cp= midstr;
	cp[0]= cp[1]= cp[2]= cp[3]= 0;
	cp[4]= ((mid >> 24) & 0xff);
	cp[5]= ((mid >> 16) & 0xff);
	cp[6]= ((mid >> 8) & 0xff);
	cp[7]= (mid & 0xff);

	/* Compute mac(message-id data) */
	cbcmac_aes_reinit(&skscp->mac);
	cbcmac_aes_update(&skscp->mac, midstr, sizeof(midstr));/* Msg ID */
	cbcmac_aes_update(&skscp->mac, in, inlen);	/* data */
	cbcmac_aes_finish(&skscp->mac, mac);

#ifdef SKSC_INSECURE_DEBUGING
	sys_printblock("mac: ", mac, sizeof(mac));
#endif

	/* Create empty IV */
	memset(env.iv, '\0', sizeof(env.iv));

	/* CFB encrypt */
	env.keyp= &skscp->key;
	env.outp= out;
	env.offset= 0;
	cfb_enc_update(&env, mac, sizeof(mac));
	cfb_enc_update(&env, in, inlen);
	cfb_enc_finish(&env);

	memset(env.block, '\0', sizeof(env.block));	/* Wipe plain text */

	assert(env.offset == 0);
	assert(env.outp == (u8_t *)out+totlen);

	skscp->message_id++;

	return totlen;
}

ssize_t sksc_decrypt(sksc_t *skscp, void *in, size_t inlen,
	void *out, size_t outlen)
{
	size_t tmplen;
	u32_t mid;
	u8_t *cp;
	u8_t mac[CMA_DIGEST_LEN];
	u8_t msg_mac[CMA_DIGEST_LEN];
	u8_t midstr[8];
	struct cfb_dec_env env;

	if (inlen < CMA_DIGEST_LEN)
	{
		/* Something went wrong */
		errno= EINVAL;
		return -1;
	}

	tmplen= inlen-CMA_DIGEST_LEN;
	if (tmplen > outlen)
	{
		/* Not enough space */
		errno= EINVAL;
		return -1;
	}

	/* No message IV */
	memset(env.iv, '\0', sizeof(env.iv));

	/* CFB decrypt */
	env.keyp= &skscp->key;
	env.inp= in;
	env.insize= inlen;
	env.offset= 0;

	cfb_dec_extract(&env, msg_mac, sizeof(msg_mac));
	cfb_dec_extract(&env, out, tmplen);
	memset(env.block, '\0', sizeof(env.block));	/* Wipe plain text */

	assert(env.inp == (u8_t *)in+inlen);

	/* Marshal message ID for HMAC. Assume 32-bit limits for now */
	mid= skscp->message_id;
	cp= midstr;
	cp[0]= cp[1]= cp[2]= cp[3]= 0;
	cp[4]= ((mid >> 24) & 0xff);
	cp[5]= ((mid >> 16) & 0xff);
	cp[6]= ((mid >> 8) & 0xff);
	cp[7]= (mid & 0xff);

	/* Compute mac(message-id || data) */
	cbcmac_aes_reinit(&skscp->mac);
	cbcmac_aes_update(&skscp->mac, midstr, 8);	/* Message ID */
	cbcmac_aes_update(&skscp->mac, out, tmplen);	/* data */
	cbcmac_aes_finish(&skscp->mac, mac);

	if (memcmp(mac, msg_mac, CMA_DIGEST_LEN) != 0)
	{
#ifdef SKSC_INSECURE_DEBUGING
		sys_printblock("mac: ", mac, CMA_DIGEST_LEN);
		sys_printblock("msg_mac: ", msg_mac, CMA_DIGEST_LEN);
#endif
		errno= EINVAL;
		return -1;
	}

	skscp->message_id++;

	return tmplen;
}

void sksc_cleanup(sksc_t *skscp)
{
	memset(skscp, '\0', sizeof(skscp));
}

static void cfb_enc_update(struct cfb_enc_env *envp, void *data, size_t size)
{
	int i, j;
	size_t n;
	ssize_t r;
	int offset;
	u8_t *cp, *ivp, *outp, *blockp;

	cp= data;
	ivp= envp->iv;
	outp= envp->outp;

	offset= envp->offset;
	if (offset)
	{
		n= SKSC_BLOCKSIZE-offset;
		if (size < n)
		{
			memcpy(&envp->block[offset], cp, size);
			envp->offset= offset+size;
			return;
		}
		memcpy(&envp->block[offset], cp, n);

		/* CFB mode encrypts the IV and XOR the plaintext with the
		 * encrypted IV
		 */
		blockp= envp->block;
		r= rijndael_ecb_encrypt(envp->keyp, ivp, outp,
			SKSC_BLOCKSIZE, NULL);
		assert(r == SKSC_BLOCKSIZE);
		for (i= 0; i<SKSC_BLOCKSIZE; i++)
			outp[i] ^= blockp[i];

		ivp= outp;	/* IV is last ciphertext block */

		cp += n;
		size -= n;
		outp += SKSC_BLOCKSIZE;

		envp->offset= 0;
	}

	n= size/SKSC_BLOCKSIZE;
	for (i= 0; i<n; i++)
	{
		/* CFB mode encrypts the IV and XOR the plaintext with the
		 * encrypted IV
		 */
		r= rijndael_ecb_encrypt(envp->keyp, ivp, outp,
			SKSC_BLOCKSIZE, NULL);
		assert(r == SKSC_BLOCKSIZE);
		for (j= 0; j<SKSC_BLOCKSIZE; j++)
			outp[j] ^= cp[j];

		ivp= outp;	/* IV is last ciphertext block */

		cp += SKSC_BLOCKSIZE;
		size -= SKSC_BLOCKSIZE;
		outp += SKSC_BLOCKSIZE;
	}

	envp->outp= outp;
	if (ivp != envp->iv)
		memcpy(envp->iv, ivp, SKSC_BLOCKSIZE);

	if (size)
	{
		memcpy(envp->block, cp, size);
		envp->offset= size;
	}
}

static void cfb_enc_finish(struct cfb_enc_env *envp)
{
	int i;
	ssize_t r;
	int offset;
	u8_t *ivp, *outp, *env_blockp;
	u8_t block[SKSC_BLOCKSIZE];

	ivp= envp->iv;
	outp= envp->outp;

	offset= envp->offset;
	if (offset)
	{
		/* CFB mode encrypts the IV and XOR the plaintext with the
		 * encrypted IV
		 */
		env_blockp= envp->block;
		r= rijndael_ecb_encrypt(envp->keyp, ivp, block,
			SKSC_BLOCKSIZE, NULL);
		assert(r == SKSC_BLOCKSIZE);
		for (i= 0; i<offset; i++)
			outp[i]= block[i] ^ env_blockp[i];

		envp->outp += offset;
		envp->offset= 0;
	}
}

static void cfb_dec_extract(struct cfb_dec_env *envp, void *data, size_t size)
{
	int i, j;
	size_t n, insize;
	ssize_t r;
	int offset;
	u8_t *cp, *inp, *ivp, *env_blockp;
	u8_t block[SKSC_BLOCKSIZE];

	cp= data;

	offset= envp->offset;
	if (offset)
	{
		n= SKSC_BLOCKSIZE-offset;
		if (size < n)
		{
			memcpy(cp, &envp->block[offset], size);
			envp->offset= offset+size;
			return;
		}
		memcpy(cp, &envp->block[offset], n);
		cp += n;
		size -= n;
		envp->offset= 0;
		if (size == 0)
			return;
	}

	n= size/SKSC_BLOCKSIZE;
	inp= envp->inp;
	insize= envp->insize;
	ivp= envp->iv;
	assert(insize >= n*SKSC_BLOCKSIZE);
	for (i= 0; i<n; i++)
	{
		r= rijndael_ecb_encrypt(envp->keyp, ivp, block,
			SKSC_BLOCKSIZE, NULL);
		assert(r == SKSC_BLOCKSIZE);
		
		for (j= 0; j<SKSC_BLOCKSIZE; j++)
			cp[j]= inp[j] ^ block[j];

		ivp= inp;	/* IV is last ciphertext block */
		inp += SKSC_BLOCKSIZE;
		insize -= SKSC_BLOCKSIZE;
		cp += SKSC_BLOCKSIZE;
		size -= SKSC_BLOCKSIZE;
	}

	if (size)
	{
		assert(size < SKSC_BLOCKSIZE);
		assert(insize >= size);
		n= SKSC_BLOCKSIZE;
		if (n > insize)
			n= insize;

		r= rijndael_ecb_encrypt(envp->keyp, ivp, block,
			SKSC_BLOCKSIZE, NULL);
		assert(r == SKSC_BLOCKSIZE);
		
		env_blockp= envp->block;
		for (i= 0; i<n; i++)
			env_blockp[i]= inp[i] ^ block[i];

		memset(block, '\0', SKSC_BLOCKSIZE);	/* Clean up */

		memcpy(cp, envp->block, size);
		envp->offset= size;

		ivp= inp;	/* IV is last ciphertext block */
		inp += n;
		insize -= n;
	}
	envp->inp= inp;
	envp->insize= insize;


	if (ivp != envp->iv)
		memcpy(envp->iv, ivp, SKSC_BLOCKSIZE);
}

#ifdef SKSC_INSECURE_DEBUGING
static void sys_printblock(char *label, void *data, size_t size)
{
	int i, j, n;
	char *strp, *cp;
	u8_t *ucp;
	int bs= 16;

	strp= malloc(bs*3+1);
	ucp= data;
	for (i= 0; size > 0; i++)
	{
		cp= strp;
		n= size;
		if (n > bs)
			n= bs;
		for (j= 0; j<n; j++, cp += strlen(cp))
			sprintf(cp, " %02x", ucp[j]);
		syslog(LOG_ERR, "%s(0x%x): %s", label, i, strp);
		ucp += n;
		size -= n;
	}
	assert(size == 0);
	free(strp);
}
#endif

/*
 * $PchId: sksc.c,v 1.1 2005/05/06 19:32:26 philip Exp $
 */
