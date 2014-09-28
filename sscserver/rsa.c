/*
rsa.c

RSA signatures

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/protocol.h"
#include "../lib/mp/libcrypt.h"
#include "../lib/rsa/rsa.h"
#include "sscserver.h"

#define PRIVKEY_TAG	"RSA3-PRIV"

static char *read_line(FILE *file);
static char *bigtoa(BigInt n);

void rsa_host_sign(char *keyfilename, SHA256_CTX *ctx)
{
	u16_t len1, len2, pad;
	size_t totlen;
	int r;
	FILE *file;
	char *line, *cp, *cp1;
	u8_t *ucp;
	void *msgp;
	struct sscp_ssig *ssig;
	BigInt n, p, s;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	file= fopen(keyfilename, "r");
	if (file == NULL)
	{
		fatal("unable to open private host key file '%s': %s",
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
			os_free(line);
			continue;
		}
		break;
	}
	fclose(file);

	/* Get size of tag */
	for (cp1= cp; cp1[0] != '\0' && cp1[0] != ' ' && cp1[0] != '\t'; cp1++)
		;	/* nothing to do */
	if (cp1-cp != sizeof(PRIVKEY_TAG)-1 ||
		strncmp(line, PRIVKEY_TAG, sizeof(PRIVKEY_TAG)-1) != 0)
	{
		fatal("unable to parse private key line '%.20s'...", line);
	}

	/* Skip white space */
	for (cp= cp1; cp[0] == ' ' || cp[0] == '\t'; cp++)
		;	/* nothing to do */
	if (cp == cp1)
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
	os_free(line);

	SHA256_Update(ctx, (unsigned char *)"S", 1);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	s= bigInit(0);
	rsa_sign(hash, n, p, s);

	reset_big(p, 0);	/* No longer needed */

	/* Send message to client */
	len1= bigBytes(n);
	len2= bigBytes(s);
	pad= 1;	/* Make sure client accepts padding */

	totlen= sizeof(*ssig) + 2+len1 + 2+len2 + pad;
	msgp= os_malloc("rsa_host_sign", totlen);
	ssig= msgp;
	u16_to_be(totlen, ssig->ss_len);
	u16_to_be(S_SSIG_TYPE, ssig->ss_type);

	/* Start of the first bignum */
	ucp= (u8_t *)(ssig+1);

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

	r= sksc_s_writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending signature message to client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	os_free(msgp);
}

int rsa_user_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH])
{
	int r;
	u16_t len, len1, len2, type, flags;
	u32_t o;
	size_t extra_len;
	u8_t *extra, *buf, *cp;
	BigInt n, s;
	struct sscp_csig csig_msg;
	SHA256_CTX pk_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	/* Get client's signature */
	r= sksc_c_readall(&csig_msg, sizeof(csig_msg));
	if (r <= 0)
	{
		fatal("error reading signature from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	len= u16_from_be(csig_msg.sc_len);
	type= u16_from_be(csig_msg.sc_type);
	flags= u16_from_be(csig_msg.sc_flags);

	if (flags)
		assert(0);

	if (type != S_CSIG_TYPE)
	{
		shutdown_fatal("bad type in client signature message: %u",
			type);
	}
	if (len < sizeof(csig_msg)+2)
	{
		shutdown_fatal("bad length in client signature message: %u",
			len);
	}

	extra_len= len-sizeof(csig_msg);
	extra= os_malloc("rsa_user_sig", extra_len);
	r= sksc_c_readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading signature from client: %s",
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
		"error decoding client's signature message (too short)");
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
		"error decoding client's signature message (too short)");
	}
	s= bigInit(0);
	bufToBig_be(extra+o, len2, s);
	o += len2;

	assert(o <= extra_len);
	os_free(extra);

	SHA256_Update(ctx, (unsigned char *)"C", 1);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	r= rsa_verify(hash, s, n);

	/* Hash public key */
	len= bigBytes(n);
	buf= os_malloc("rsa_user_sig", len);
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
	struct sscp_rusig *rusig;
	BigInt n, p, s;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if (keyfilename != NULL)
	{
		file= fopen(keyfilename, "r");
		if (file == NULL)
		{
			syslog(LOG_INFO,
			"unable to open private host key file '%s': %s",
				keyfilename, strerror(errno));
			keyfilename= NULL;
		}
	}

	/* Do we want another key in case the user doesn't have one? */

	if (keyfilename != NULL)
	{
		for (;;)
		{
			line= read_line(file);
			if (line == NULL)
			{
				fatal("No key found in file '%s'",
					keyfilename);
			}

			/* Skip leading white space */
			for (cp= line; cp[0] == ' ' || cp[0] == '\t'; cp++)
				; /* do nothing */
			if (cp[0] == '#')
			{
				/* Skip comment lines */
				os_free(line);
				continue;
			}
			break;
		}
		fclose(file);

		if (strncmp(line, PRIVKEY_TAG, sizeof(PRIVKEY_TAG)-1) != 0)
		{
			fatal("unable to parse private key line '%.20s'...",
				line);
		}

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
		os_free(line);
	}
	else
	{
		n= bigInit(1);
		p= bigInit(1);
	}

	SHA256_Update(ctx, (unsigned char *)"RU", 2);
	SHA256_Final(hash, ctx);

	assert(RSA_HASH_LEN == SHA256_DIGEST_LENGTH);
	s= bigInit(0);
	rsa_sign(hash, n, p, s);

	reset_big(p, 0);	/* No longer needed */

	/* Send message to client */
	len1= bigBytes(n);
	len2= bigBytes(s);
	pad= 1;	/* Make sure client support padding */

	totlen= sizeof(*rusig) + 2+len1 + 2+len2 + pad;
	msgp= os_malloc("rsa_user_sign", totlen);
	rusig= msgp;
	u16_to_be(totlen, rusig->sr_len);
	u16_to_be(S_RUSIG_TYPE, rusig->sr_type);
	u16_to_be(keyfilename == NULL ? S_RUSIG_F_INVALID : 0,
		rusig->sr_flags);

	/* Start of the first bignum */
	ucp= (u8_t *)(rusig+1);

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

	r= sksc_s_writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending user signature message to client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	os_free(msgp);
}

static char *read_line(FILE *file)
{
	char *line;
	size_t offset, size, len;

	size= 80;
	offset= 0;
	line= os_malloc("read_line", size);
	for (;;)
	{
		if (offset+1 >= size)
		{
			size *= 2;
			line= os_realloc("read_line", line, size);
		}
		assert(offset+1 < size);
		if (fgets(line+offset, size-offset, file) == NULL)
		{
			if (feof(file))
			{
				if (offset == 0)
				{
					os_free(line);
					return NULL;
				}
				fatal("unexpected end of key file");
			}
			fatal("error reading key file: %s", strerror(errno));
		}
		len= strlen(line+offset);
		if (len == 0)
			fatal("unexpected end of key file, got '%s'", line);
		offset += len;
		if (line[offset-1] == '\n')
			break;
	}
	line[offset-1]= '\0';
	return line;
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
 * $PchId: rsa.c,v 1.2 2005/06/01 10:25:23 philip Exp $
 */
