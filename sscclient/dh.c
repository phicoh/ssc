/*
dh.c

Diffie-Hellman key agreement protocol

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../lib/mp/libcrypt.h"
#include "../lib/dh/dh.h"
#include "../lib/sha2/sha2.h"

#include "../include/os.h"
#include "../include/protocol.h"
#include "sscclient.h"

void do_dh(struct sscp_version *version_msgp, prnd_t *prndp, 
	u32_t *maxmsglenp, 
	SHA256_CTX *prot_ctx, SHA256_CTX *dhsec_ctx)
{
	int r, p_bits, q_bits, fail_maxmsglen, fail_modbits;
	u16_t len, len1, len2, len3, len4, type;
	u32_t o, maxmsglen;
	size_t extra_len;
	u8_t *extra, *cp, *buf;
	struct sscp_cpk *cpk_msgp;
	BigInt p, q, g, gx, y, gy, gxy;
	struct
	{
		struct sscp_version v;
		struct sscp_cpp cpp;
	} msg;
	struct sscp_spp spp_msg;

	msg.v= *version_msgp;

	u16_to_be(sizeof(msg.cpp), msg.cpp.sc_len);
	u16_to_be(S_CPP_TYPE, msg.cpp.sc_type);
	u32_to_be(S_CPP_MAXMSGLEN, msg.cpp.sc_maxmsglen);
	u32_to_be(S_CPP_MODMIN, msg.cpp.sc_modmin);

	len= sizeof(msg.v)+sizeof(msg.cpp);
	SHA256_Update(prot_ctx, (unsigned char *)&msg, len);
	r= writeall(&msg, len);
	if (r <= 0)
	{
		fatal("error sending version and parameters to server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	r= readall(&spp_msg, sizeof(spp_msg));
	if (r <= 0)
	{
		fatal("error reading parameters from server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	SHA256_Update(prot_ctx, (unsigned char *)&spp_msg, sizeof(spp_msg));
	len= u16_from_be(spp_msg.ss_len);
	type= u16_from_be(spp_msg.ss_type);
	maxmsglen= u32_from_be(spp_msg.ss_maxmsglen);
	*maxmsglenp= maxmsglen;

	if (type != S_SPP_TYPE)
	{
		shutdown_fatal("bad type in server parameter message: %u",
			type);
	}
	if (len < sizeof(spp_msg)+2)
	{
		shutdown_fatal("bad length in server parameter message: %u",
			len);
	}

	extra_len= len-sizeof(spp_msg);
	extra= os_malloc("do_dh", extra_len);
	r= readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading parameters from server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	SHA256_Update(prot_ctx, extra, extra_len);
	o= 0;

	/* Modulus */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's parameter message (too short)");
	}
	p= bigInit(0);
	bufToBig_be(extra+o, len1, p);
	o += len1;

	/* Sub-group */
	assert(o+2 <= extra_len);
	len2= u16_from_be(extra+o);
	o += 2;
	if (o+len2+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's parameter message (too short)");
	}
	q= bigInit(0);
	bufToBig_be(extra+o, len2, q);
	o += len2;

	/* Generator */
	assert(o+2 <= extra_len);
	len3= u16_from_be(extra+o);
	o += 2;
	if (o+len3+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's parameter message (too short)");
	}
	g= bigInit(0);
	bufToBig_be(extra+o, len3, g);
	o += len3;

	/* Public Key */
	assert(o+2 <= extra_len);
	len4= u16_from_be(extra+o);
	o += 2;
	if (o+len4 > extra_len)
	{
		shutdown_fatal(
		"error decoding server's parameter message (too short)");
	}
	gx= bigInit(0);
	bufToBig_be(extra+o, len4, gx);
	o += len4;

	if (o < extra_len)
	{
		shutdown_fatal(
		"error decoding server's parameter message (too long)");
	}
	free(extra);

	if (maxmsglen == S_SPP_MAXMSGLEN_ERROR)
		shutdown_fatal("server did not accept max. msg. len");

	if (bigCompare(p, zero) == 0)
		shutdown_fatal("server did not accept modulus size");

	if (maxmsglen > S_CPP_MAXMSGLEN)
	{
		shutdown_fatal("server increased max. msg. length to %u",
			maxmsglen);
	}

	fail_maxmsglen= 0;
	fail_modbits= 0;

	if (maxmsglen < S_SPP_MAXMSGLEN_MIN)
		fail_maxmsglen= 1;

	/* Check modulus size */
	p_bits= bigBits(p);
	if (p_bits < S_CPP_MODMIN)
		shutdown_fatal("modulus too small: %u", p_bits);
	if (p_bits > S_SPP_MOD_MAX)
		fail_modbits= 1;

	if (fail_maxmsglen || fail_modbits)
	{
		y= bigInit(0);
		gy= bigInit(0);
	}
	else
	{
		/* Generate DH secret key */
		y= bigInit(0);
		dh_rnd_x(q, prndp, y);

		/* DH public key */
		gy= bigInit(0);
		dh_gx(g, y, p, gy);
	}

	len1= bigBytes(gy);
	len= sizeof(*cpk_msgp) + 2+len1;
	cpk_msgp= os_malloc("do_dh", len);
	u16_to_be(len, cpk_msgp->sc_len);
	u16_to_be(S_CPK_TYPE, cpk_msgp->sc_type);

	/* Store public key */
	cp= (u8_t *)(cpk_msgp+1);
	u16_to_be(len1, cp);
	cp += 2;
	bigToBuf_be(gy, len1, cp);
	cp += len1;

	assert(cp == (u8_t *)cpk_msgp + len);

	SHA256_Update(prot_ctx, (unsigned char *)cpk_msgp, len);
	r= writeall(cpk_msgp, len);
	if (r <= 0)
	{
		fatal("error sending DH pubick key to server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	if (fail_maxmsglen)
	{
		shutdown_fatal("server max. msg. length too small: %u",
			maxmsglen);
	}
	if (fail_modbits)
	{
		shutdown_fatal("server modulus too large: %u bits",
			p_bits);
	}

	/* Check sub-group size */
	q_bits= bigBits(q);
	if (q_bits != S_SPP_SUBGROUP_BITS)
	{
		shutdown_fatal("wrong sub-group size: %u", q_bits);
	}

	/* Do we want to check whether p and q are prime? If p or q is not
	 * a prime, we probably have an insecure Diffie-Hellman group. We
	 * can assume that the server sends a correct group. In a secure
	 * connection (if we know the server's RSA public key) we can detect
	 * tempering. In an insecure connection, we may be subject to a
	 * man in the middle attack anyhow. Checking whether a number is prime
	 * is relatively expensive. We could cache the results. Do we want
	 * the additional complexitiy? For now, just check whether q divides
	 * p-1.
	 */
	if (!dh_check_q_fast(p, q))
		shutdown_fatal("bad sub-group");
	if (!dh_check_gx(g, p, q))
		shutdown_fatal("bad generator");
	if (!dh_check_gx(gx, p, q))
		shutdown_fatal("bad server DH public key");

	/* Compute shared secret */
	gxy= bigInit(0);
	dh_gx(gx, y, p, gxy);

	/* Hash shared secret */
	len= bigBytes(gxy);
	buf= os_malloc("do_dh", len);
	bigToBuf_be(gxy, len, buf);

	/* Get rid of leading zeros */
	for (cp= buf; *cp == '\0' && cp < buf+len; cp++)
		;	/* No nothing */
	assert(cp < buf+len);
	SHA256_Update(dhsec_ctx, cp, buf+len-cp);

	free(buf);

	freeBignum(p);
	freeBignum(q);
	freeBignum(g);
	freeBignum(gx);
	reset_big(y, 0);	/* Just in case */
	freeBignum(y);
	freeBignum(gy);
	reset_big(gxy, 0);	/* Just in case */
	freeBignum(gxy);
}

/*
 * $PchId: dh.c,v 1.2 2005/06/01 10:23:14 philip Exp $
 */
