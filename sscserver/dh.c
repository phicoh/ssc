/*
dh.c

Diffie-Hellman key agreement protocol

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/protocol.h"
#include "../lib/dh/dh.h"
#include "../lib/mp/libcrypt.h"
#include "sscserver.h"

static struct group_table
{
	int modsize;
	char *mod_str;
	char *subgroup_str;
	char *generator_str;
} group_table[]=
{
	{
		2048,
		"c0dd7ecbe61bb29caabd096acb49866adaa30b2039119e8c857395c3a36c"
		"8643768323edfabfca5fb8bd7a392d976ff71ef69afb9b23ce814a28fc0a"
		"12d428519342690251266efd15d24b4e66dec7394e31ae8ce87f7a893899"
		"def93e525f399f68797ad96e4f15d7ad6adf8bdbdfab1feba05e9e35a92d"
		"bad7b62ad217e8385c70971a58eb62558b053721c583339963f03bf250be"
		"6ff4e62f4d888dc9dfa868c803714de05fea90181a4b611141b841214447"
		"7fd76b82f4c02c35a82d00cf83c8e5df13eef8e99ca2a28ae039338289a9"
		"f694aa932ac704c2e3eb1a17e51ce2353786acbbdcb78271f8b84c927d86"
		"d7e1ca14ac5c971bf9d2593ddb040f2f",
		"cf178a97ae6c7a092572b8fb6bd712859d0ea1ad90167ec7baba713b16cd"
		"2ea3",
		"8fb16e44835390cdd46d9387ecfa94afe1a25a86305f35dea867d107ee55"
		"c809ffed119c652303bbd811f68482c2a2414988482b72ded59d5f420ec1"
		"f16c8862c67a9b86836569a7b1df276e3af09cfd52fbc5f2143ca0c303ef"
		"f9689462bb12d8f4584c69b509bb0ff7f24b26a5d93cbdb77ee48a47968f"
		"53caf99c9308e82a3c3c21bb15d6d254b1435b330c136808572ee06f2629"
		"9c79bfa8406b98cd590c65b7608d7a601f25232813a3f94ef4a3fec72e61"
		"881e764e7c4af7c9e837cf2663e9b43b1356fb42d09026a996ed6cc955e8"
		"b2255ac31d5e708998b399a25a3da1bf670b5a1c2957a68dc41386b10704"
		"06b3cf59a7ac350a123ec3adf0a71502"
	},
	{ 0, NULL, NULL, NULL }
};

void do_dh(prnd_t *prndp, u32_t *maxmsglenp, 
	SHA256_CTX *prot_ctx, SHA256_CTX *dhsec_ctx)
{
	int i, r;
	u16_t len, type, len1, len2, len3, len4, extra_len;
	u32_t o, maxmsglen, client_maxmsglen, modmin;
	int modsize;
	size_t totlen;
	void *msgp;
	u8_t *cp, *extra, *buf;
	BigInt p, q, g, x, gx, gy, gyx;
	struct group_table *bestp;
	struct sscp_spp *sppp;
	struct sscp_cpp cpp;
	struct sscp_cpk cpk_msg;

	/* Get client parameters */
	r= readall(&cpp, sizeof(cpp));
	if (r <= 0)
	{
		fatal("error reading parameter message from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	SHA256_Update(prot_ctx, (unsigned char *)&cpp, sizeof(cpp));

	len= u16_from_be(cpp.sc_len);
	type= u16_from_be(cpp.sc_type);
	client_maxmsglen= u32_from_be(cpp.sc_maxmsglen);
	modmin= u32_from_be(cpp.sc_modmin);

	if (type != S_CPP_TYPE)
	{
		shutdown_fatal("bad type in client parameters message: %u\n",
			type);
	}
	if (len != sizeof(cpp))
	{
		shutdown_fatal("bad length in client parameters message: %u\n",
			len);
	}
	
	/* Find suitable DH parameters */
	bestp= NULL;
	for (i= 0; group_table[i].modsize != 0; i++)
	{
		modsize= group_table[i].modsize;
		if (modsize < modmin)
			continue;	/* Too small */
		if (bestp && modsize > bestp->modsize)
			continue;	/* Too large */
		bestp= &group_table[i];
	}

	if (!bestp)
	{
		p= bigInit(0);
		q= bigInit(0);
		g= bigInit(0);
		x= bigInit(0);
		gx= bigInit(0);
	}
	else
	{
		p= atobig(bestp->mod_str);
		q= atobig(bestp->subgroup_str);
		g= atobig(bestp->generator_str);

		/* Generate DH secret key */
		x= bigInit(0);
		dh_rnd_x(q, prndp, x);

		/* DH public key */
		gx= bigInit(0);
		dh_gx(g, x, p, gx);

	}

	maxmsglen= client_maxmsglen;
	if (maxmsglen > S_SPP_MAXMSGLEN)
		maxmsglen= S_SPP_MAXMSGLEN;
	if (maxmsglen < S_CPP_MAXMSGLEN_MIN)
		maxmsglen= S_SPP_MAXMSGLEN_ERROR;
	*maxmsglenp= maxmsglen;

	len1= bigBytes(p);
	len2= bigBytes(q);
	len3= bigBytes(g);
	len4= bigBytes(gx);

	totlen= sizeof(*sppp) + 2+len1 + 2+len2 + 2+len3 + 2+len4;
	msgp= os_malloc("do_dh", totlen);
	sppp= msgp;
	u16_to_be(totlen, sppp->ss_len);
	u16_to_be(S_SPP_TYPE, sppp->ss_type);
	u32_to_be(maxmsglen, sppp->ss_maxmsglen);

	/* Start of the first bignum */
	cp= (u8_t *)(sppp+1);

	/* Modulus p */
	u16_to_be(len1, cp);
	cp += 2;
	bigToBuf_be(p, len1, cp);
	cp += len1;

	/* Sub-group q */
	u16_to_be(len2, cp);
	cp += 2;
	bigToBuf_be(q, len2, cp);
	cp += len2;

	/* Generator g */
	u16_to_be(len3, cp);
	cp += 2;
	bigToBuf_be(g, len3, cp);
	cp += len3;

	/* Public key gx */
	u16_to_be(len4, cp);
	cp += 2;
	bigToBuf_be(gx, len4, cp);
	cp += len4;

	assert(cp == (u8_t *)msgp+totlen);

	SHA256_Update(prot_ctx, msgp, totlen);
	r= writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending parameter message to client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	if (maxmsglen == 0)
	{
		shutdown_fatal("max. msg. len too small: %u",
			client_maxmsglen);
	}

	if (bestp == NULL)
		shutdown_fatal("request modulus size too large: %u", modmin);

	os_free(msgp);

	r= readall(&cpk_msg, sizeof(cpk_msg));
	if (r <= 0)
	{
		fatal("error reading public key message from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	SHA256_Update(prot_ctx, (unsigned char *)&cpk_msg, sizeof(cpk_msg));
	len= u16_from_be(cpk_msg.sc_len);
	type= u16_from_be(cpk_msg.sc_type);

	if (type != S_CPK_TYPE)
	{
		shutdown_fatal("bad type in client public key message: %u",
			type);
	}
	if (len < sizeof(cpk_msg)+2)
	{
		shutdown_fatal("bad length in client public key message: %u",
			len);
	}

	extra_len= len-sizeof(cpk_msg);
	extra= os_malloc("do_dh", extra_len);
	r= readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading public key from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	SHA256_Update(prot_ctx, extra, extra_len);
	o= 0;

	/* Public Key */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1 > extra_len)
	{
		shutdown_fatal(
		"error decoding client public key message (too short)");
	}
	gy= bigInit(0);
	bufToBig_be(extra+o, len1, gy);
	o += len1;

	if (o != extra_len)
	{
		shutdown_fatal(
		"error decoding client public key message (too long)");
	}

	os_free(extra);

	if (bigCompare(gy, zero) == 0)
	{
		shutdown_fatal(
		"client did not accept max. msg. length or modulus size");
	}

	/* Check the client's public key */
	if (!dh_check_gx(gy, p, q))
		shutdown_fatal("bad client DH public key");

	/* Compute shared secret */
	gyx= bigInit(0);
	dh_gx(gy, x, p, gyx);

	/* Hash shared secret */
	len= bigBytes(gyx);
	buf= os_malloc("do_dh", len);
	bigToBuf_be(gyx, len, buf);

	/* Get rid of leading zeros */
	for (cp= buf; *cp == '\0' && cp < buf+len; cp++)
		;	/* No nothing */
	assert(cp < buf+len);
	SHA256_Update(dhsec_ctx, cp, buf+len-cp);

	os_free(buf);

	freeBignum(p);
	freeBignum(q);
	freeBignum(g);
	reset_big(x, 0);	/* Just in case */
	freeBignum(x);
	freeBignum(gx);
	freeBignum(gy);
	reset_big(gyx, 0);	/* Just in case */
	freeBignum(gyx);
}

/*
 * $PchId: dh.c,v 1.1 2005/05/25 14:01:49 philip Exp $
 */
