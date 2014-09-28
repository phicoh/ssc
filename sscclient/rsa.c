/*
rsa.c

RSA signatures

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../lib/mp/libcrypt.h"
#include "../lib/prnd/prnd.h"
#include "../lib/rsa/rsa.h"
#include "../lib/sha2/sha2.h"

#include "../include/os.h"
#include "../include/protocol.h"
#include "sscclient.h"

#define PRIVKEY_TAG	"RSA3-PRIV"

static char *bigtoa(BigInt n);

int rsa_server_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH])
{
	int r;
	u16_t len, len1, len2, type;
	u32_t o;
	size_t extra_len;
	u8_t *extra, *buf, *cp;
	BigInt n, s;
	struct sscp_ssig ssig_msg;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX pk_ctx;

	/* Get server's signature */
	r= sksc_s_readall(&ssig_msg, sizeof(ssig_msg));
	if (r <= 0)
	{
		fatal("error reading signature from server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	len= u16_from_be(ssig_msg.ss_len);
	type= u16_from_be(ssig_msg.ss_type);

	if (type != S_SSIG_TYPE)
	{
		shutdown_fatal("bad type in server signature message: %u",
			type);
	}
	if (len < sizeof(ssig_msg)+2)
	{
		shutdown_fatal("bad length in server signature message: %u",
			len);
	}

	extra_len= len-sizeof(ssig_msg);
	extra= os_malloc("rsa_server_sig", extra_len);
	r= sksc_s_readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading signature from server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	o= 0;

	/* Modulus */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's signature message (too short)");
	}
	n= bigInit(0);
	bufToBig_be(extra+o, len1, n);
	o += len1;

	/* Signature */
	assert(o+2 <= extra_len);
	len2= u16_from_be(extra+o);
	o += 2;
	if (o+len2 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's signature message (too short)");
	}
	s= bigInit(0);
	bufToBig_be(extra+o, len2, s);
	o += len2;

	assert (o <= extra_len);
	free(extra);

	SHA256_Update(ctx, (unsigned char *)"S", 1);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	r= rsa_verify(hash, s, n);

	/* Hash public key */
	len= bigBytes(n);
	buf= os_malloc("rsa_server_sig", len);
	bigToBuf_be(n, len, buf);

	/* Get rid of leading zeros */
	for (cp= buf; *cp == '\0' && cp < buf+len; cp++)
		;	/* No nothing */
	assert(cp < buf+len);
	SHA256_Init(&pk_ctx);
	SHA256_Update(&pk_ctx, cp, buf+len-cp);
	SHA256_Final(pk_hash, &pk_ctx);

	freeBignum(n);
	freeBignum(s);

	if (!r)
		return -1;

	return 0;
}

void rsa_user_sign(char *keyfilename, SHA256_CTX *ctx)
{
	u16_t len1, len2, pad;
	size_t totlen;
	int r;
	FILE *file;
	char *line, *cp, *cp1;
	u8_t *ucp;
	void *msgp;
	struct sscp_csig *csig;
	BigInt n, p, s;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	file= fopen(keyfilename, "r");
	if (file == NULL)
	{
		fatal("unable to open private key file '%s': %s",
			keyfilename, strerror(errno));
	}
	for (;;)
	{
		line= read_line(file);
		if (line == NULL)
			fatal("No key found in file '%s'", keyfilename);

		/* Skip leading white space */
		for (cp= line; cp[0] == ' ' || cp[0] == '\t'; cp++)
			; /* do nothing */
		if (cp[0] == '#')
		{
			/* Skip comment lines */
			free(line);
			continue;
		}
		break;
	}
	fclose(file);

	if (strncmp(line, PRIVKEY_TAG, sizeof(PRIVKEY_TAG)-1) != 0)
		fatal("unable to parse private key line '%.20s'...", line);

	/* Skip white space */
	for (cp= line+sizeof(PRIVKEY_TAG)-1;
		cp[0] == ' ' || cp[0] == '\t'; cp++)
	{
		/* nothing to do */
	}
	if (cp == line+sizeof(PRIVKEY_TAG)-1)
	{
		fatal(
		"no white space after tag in private key line '%.20s'...",
			line);
	}
	cp1= strchr(cp, ':');
	if (cp1 == NULL)
		fatal("no colon in private key line '%.20s'...", line);
	/* XXX -- Should fix atobig. */
	*cp1= '\0';
	n= atobig(cp);
	*cp1= ':';
	p= atobig(cp1+1);
	free(line);

	SHA256_Update(ctx, (unsigned char *)"C", 1);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	s= bigInit(0);
	rsa_sign(hash, n, p, s);

	reset_big(p, 0);	/* No longer needed */

	/* Send message to server */
	len1= bigBytes(n);
	len2= bigBytes(s);
	pad= 1;	/* Make sure the server accepts padding */

	totlen= sizeof(*csig) + 2+len1 + 2+len2 + pad;
	msgp= os_malloc("rsa_user_sign", totlen);
	csig= msgp;
	u16_to_be(totlen, csig->sc_len);
	u16_to_be(S_CSIG_TYPE, csig->sc_type);
	u16_to_be(0, csig->sc_flags);

	/* Start of the first bignum */
	ucp= (u8_t *)(csig+1);

	/* Modulus n */
	u16_to_be(len1, ucp);
	ucp += 2;
	bigToBuf_be(n, len1, ucp);
	ucp += len1;

	/* Signature s */
	u16_to_be(len2, ucp);
	ucp += 2;
	bigToBuf_be(s, len2, ucp);
	ucp += len2;

	/* Padding */
	memset(ucp, '\0', pad);
	ucp += pad;

	assert(ucp == (u8_t *)msgp+totlen);

	r= sksc_c_writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending signature message to server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	free(msgp);
}

int rsa_remuser_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH],
	int *nosigp)
{
	int r;
	u16_t len, len1, len2, type, flags;
	u32_t o;
	size_t extra_len;
	u8_t *extra, *buf, *cp;
	BigInt n, s;
	struct sscp_rusig rusig_msg;
	SHA256_CTX pk_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	*nosigp= 1;	/* Assume no signature */

	/* Get server's signature */
	r= sksc_s_readall(&rusig_msg, sizeof(rusig_msg));
	if (r <= 0)
	{
		fatal("error reading signature from remote user: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	len= u16_from_be(rusig_msg.sr_len);
	type= u16_from_be(rusig_msg.sr_type);
	flags= u16_from_be(rusig_msg.sr_flags);

	if (type != S_RUSIG_TYPE)
	{
		shutdown_fatal("bad type in remote user signature message: %u",
			type);
	}
	if (len < sizeof(rusig_msg)+2)
	{
		shutdown_fatal(
		"bad length in remote user signature message: %u",
			len);
	}

	extra_len= len-sizeof(rusig_msg);
	extra= os_malloc("rsa_remuser_sig", extra_len);
	r= sksc_s_readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading remote user signature: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	o= 0;

	/* Modulus */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding remote user's signature message (too short)");
	}
	n= bigInit(0);
	bufToBig_be(extra+o, len1, n);
	o += len1;

	/* Signature */
	assert(o+2 <= extra_len);
	len2= u16_from_be(extra+o);
	o += 2;
	if (o+len2 > extra_len)
	{
		shutdown_fatal(
		"error decoding remote user's signature message (too short)");
	}
	s= bigInit(0);
	bufToBig_be(extra+o, len2, s);
	o += len2;

	assert(o <= extra_len);
	free(extra);

	SHA256_Update(ctx, (unsigned char *)"RU", 2);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	r= rsa_verify(hash, s, n);

	/* Hash public key */
	len= bigBytes(n);
	buf= os_malloc("rsa_remuser_sig", len);
	bigToBuf_be(n, len, buf);

	/* Get rid of leading zeros */
	for (cp= buf; *cp == '\0' && cp < buf+len; cp++)
		;	/* No nothing */
	assert(cp < buf+len);
	SHA256_Init(&pk_ctx);
	SHA256_Update(&pk_ctx, cp, buf+len-cp);
	SHA256_Final(pk_hash, &pk_ctx);

	freeBignum(n);
	freeBignum(s);

	if (flags & S_RUSIG_F_INVALID)
	{
		/* No signature is reported as a valid signature with
		 * a hash that consists of zero bytes.
		 */
		memset(pk_hash, '\0', SHA256_DIGEST_LENGTH);
		return 0;
	}

	*nosigp= 0;	/* Signature present */

	if (!r)
		return -1;

	return 0;
}

static char *bigtoa(BigInt n)
{
	static char *str= NULL;

	size_t len;

	len= bigBytes(n)*2+1;
	str= os_realloc("bigtoa", str, len);
	bigsprint(n, (unsigned char *)str);
	return str;
}

/*
 * $PchId: rsa.c,v 1.2 2005/06/01 10:23:55 philip Exp $
 */
