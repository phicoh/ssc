/*
sscserver.c

Implementation of the server side of a secure channel

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"

#include "../lib/sha2/sha2.h"
#include "../lib/sksc/sksc.h"
#include "../include/protocol.h"
#include "../include/sscversion.h"
#include "sscserver.h"

#if 1
char *sfile_name= "/etc/ssc/services";
#else	/* For Android, should be configured in os.h */
char *sfile_name= "/data/ssc/services";
#endif

static char *progname;

static struct
{
	u32_t version;
} version_table[]=
{
	{ SV_VERSION_ONE },
	{ 0 }			/* end of list */
};

u32_t maxmsglen;

static sksc_t sksc_c;		/* Symmetric key secure channel, from client to
				 * server.
				 */
static u8_t sksc_c_inbuf[S_SPP_MAXMSGLEN + SKSC_OVERHEAD];
static u8_t sksc_c_buf[S_SPP_MAXMSGLEN];	/* Decoded results */
static size_t sksc_c_currsize, sksc_c_offset;
static sksc_t sksc_s;		/* Symmetric key secure channel, from server
 				 * to client.
				 */
static u8_t sksc_s_outbuf[4 + S_SPP_MAXMSGLEN + SKSC_OVERHEAD];

#define HOST_KEY	"/etc/ssc/host-priv"
#if 0	/* For Android, should be configured in os.h */
#undef HOST_KEY
#define HOST_KEY	"/data/ssc/host-priv"
#endif

static void do_version(SHA256_CTX *ctx);
static void init_sksc(SHA256_CTX *dhsec_ctx);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, r;
	char *user_key_file;
	prnd_t prnd;
	SHA256_CTX prot_hash_ctx, dhsec_hash_ctx,
		client_hash_ctx, server_hash_ctx, user_hash_ctx;
	unsigned char pk_hash[SHA256_DIGEST_LENGTH];

	openlog("sscserver", LOG_CONS, LOG_AUTH);

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	while (c= getopt(argc, argv, "V?"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'V':
			fprintf(stderr, "%s: version %s\n", 
				progname, sscversion);
			exit(1);
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	if (optind != argc)
		usage();

	SHA256_Init(&prot_hash_ctx);
	SHA256_Init(&dhsec_hash_ctx);

	do_version(&prot_hash_ctx);
	prnd_init(&prnd, NULL, 0);
	do_dh(&prnd, &maxmsglen, &prot_hash_ctx, &dhsec_hash_ctx);

	client_hash_ctx= prot_hash_ctx;
	server_hash_ctx= prot_hash_ctx;
	user_hash_ctx= prot_hash_ctx;

	init_sksc(&dhsec_hash_ctx);

	/* Don't leak any data */
	memset(&dhsec_hash_ctx, '\0', sizeof(dhsec_hash_ctx));

	rsa_host_sign(HOST_KEY, &server_hash_ctx);

	r= rsa_user_sig(&client_hash_ctx, pk_hash);
	if (r < 0)
		fatal("client sent invalid signature");

	get_user_service();

	user_key_file= auth_user_key_file();
	rsa_user_sign(user_key_file, &user_hash_ctx);
	os_free(user_key_file);

	get_password();

	check_access_pk(pk_hash);
	check_access_password();

	/* Access status returns only if access has been granted. An extra
	 * safety catch does not hurt.
	 */
	r= access_status();
	if (r != 0)
	{
		fatal("access_status failed");
		return 1;	/* Just in case */
	}

	do_service();

	return 0;
}

int readall(void *buf, size_t size)
{
	char *p;
	size_t o;
	ssize_t r;

	p= buf;
	o= 0;
	while (o < size)
	{
		r= read(0, &p[o], size-o);
		if (r <= 0)
		{
			if (r == -1 && errno == EINTR)
				continue;
			return r;
		}
		o += r;
	}
	assert (o == size);
	return size;
}

int writeall(void *buf, size_t size)
{
	char *p;
	size_t o;
	ssize_t r;

	p= buf;
	o= 0;
	while (o < size)
	{
		r= write(1, &p[o], size-o);
		if (r <= 0)
		{
			if (r == -1 && errno == EINTR)
				continue;
			return r;
		}
		o += r;
	}
	assert (o == size);
	return size;
}

int sksc_c_readall(void *buf, size_t size)
{
	int r;
	u8_t len_bytes[4];
	u32_t len;

	if (sksc_c_offset >= sksc_c_currsize)
	{
		assert(sksc_c_offset == sksc_c_currsize);

		r= readall(len_bytes, sizeof(len_bytes));
		if (r <= 0)
		{
			if (r == 0)
				fatal("got unexpected EOF from client");
			return r;
		}
		len= u32_from_be(len_bytes);
		if (len < 4)
		{
			fatal(
			"sksc_c_readall got bad length from server: %u",
				len);
		}
		len -= 4;
		if (len > maxmsglen+SKSC_OVERHEAD)
		{
			fatal("sksc_c_readall got bad length from server: %u",
				len+4);
		}
		assert(maxmsglen <= S_CPP_MAXMSGLEN);
		r= readall(sksc_c_inbuf, len);
		if (r <= 0)
		{
			if (r == 0)
				fatal("got unexpected EOF from client");
			return r;
		}
		r= sksc_decrypt(&sksc_c, sksc_c_inbuf, len,
			sksc_c_buf, sizeof(sksc_c_buf));
		if (r < 0)
		{
			syslog(LOG_ERR,
"sksc_c_readall: sksc_decrypt failed: len = %d, sizeof(sksc_c_buf) = %d\n",
				len, sizeof(sksc_c_buf));
			return r;
		}
		if (r == 0)
			return r;

		sksc_c_offset= 0;
		sksc_c_currsize= r;
	}

	if (sksc_c_currsize-sksc_c_offset < size)
	{
		fatal("sksc_c_readall: read request too big %u > %u",
			size, sksc_c_currsize-sksc_c_offset);
	}
	memcpy(buf, sksc_c_buf+sksc_c_offset, size);
	
	sksc_c_offset += size;
	return size;
}

int sksc_s_writeall(void *data, size_t len)
{
	int r;

	assert(maxmsglen <= S_SPP_MAXMSGLEN);
	if (len > maxmsglen)
	{
		errno= EINVAL;
		return -1;
	}
	r= sksc_encrypt(&sksc_s, data, len, sksc_s_outbuf+4,
		sizeof(sksc_s_outbuf)-4);
	if (r < len)
		fatal("sksc_encrypt failed");
	u32_to_be(r+4, sksc_s_outbuf);
	r= writeall(sksc_s_outbuf, r+4);
	return r;
}


void u16_to_be(u16_t v, u8_t buf[2])
{
	buf[0]= ((v >> 8) & 0xff);
	buf[1]= (v & 0xff);
}

void u32_to_be(u32_t v, u8_t buf[4])
{
	buf[0]= ((v >> 24) & 0xff);
	buf[1]= ((v >> 16) & 0xff);
	buf[2]= ((v >> 8) & 0xff);
	buf[3]= (v & 0xff);
}

u16_t u16_from_be(u8_t buf[2])
{
	return ((u16_t)buf[0] << 8) | buf[1];
}

u32_t u32_from_be(u8_t buf[4])
{
	return ((u32_t)buf[0] << 24) | ((u32_t)buf[1] << 16) |
		((u32_t)buf[2] << 8) | buf[3];
}

void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}

void shutdown_fatal(char *fmt, ...)
{
	va_list ap;

	/* First report the error */
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	/* and then try to shutdown the connection */
	tcp_shutdown(0);

	exit(1);
}

static void do_version(SHA256_CTX *ctx)
{
	int i, r;
	struct sscp_version version_msg;
	u32_t v, best, prev_version, client_version;

	/* Start with the highest possible version number */
	prev_version= 0xffffffff;

	for (;;)
	{
		/* Find the highest version we support that is less than
		 * or equal to the clients's version.
		 */
		best= SV_VERSION_ERROR;
		for (i= 0; version_table[i].version != 0; i++)
		{
			v= version_table[i].version;
			if (v > prev_version)
				continue;	/* Too high */
			if (v < best)
				continue;	/* Not the highest */
			best= v;
		}

		/* Send the (new) version number. */
		memcpy(version_msg.sv_label, SV_LABEL,
			sizeof(version_msg.sv_label));
		version_msg.sv_version[0]= ((best >> 24) & 0xff);
		version_msg.sv_version[1]= ((best >> 16) & 0xff);
		version_msg.sv_version[2]= ((best >> 8) & 0xff);
		version_msg.sv_version[3]= (best & 0xff);
		SHA256_Update(ctx, (unsigned char *)&version_msg,
			sizeof(version_msg));
		r= writeall(&version_msg, sizeof(version_msg));
		if (r <= 0)
		{
			fatal("error sending version message to client: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}

		if (best == SV_VERSION_ERROR)
		{
			shutdown_fatal(
			"cannot find version to match client's version 0x%x",
				prev_version);
		}
		prev_version= best;

		/* Get the protocol version number from the client. */
		r= readall(&version_msg, sizeof(version_msg));
		if (r <= 0)
		{
			fatal("error reading version message from client: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}
		SHA256_Update(ctx, (unsigned char *)&version_msg,
			sizeof(version_msg));
		if (memcmp(version_msg.sv_label, SV_LABEL,
			sizeof(version_msg.sv_label)) != 0)
		{
			shutdown_fatal("bad label in version message");
		}
		client_version= u32_from_be(version_msg.sv_version);
		if (client_version == SV_VERSION_ERROR)
			shutdown_fatal("client sent error version");

		/* Consistency check. The client's version number should
		 * be less then or equal to prev_version.
		 */
		if (client_version > prev_version)
		{
			shutdown_fatal(
			"client sent bad version number (0x%x) (>= 0x%x)",
				client_version, prev_version);
		}
		if (client_version == prev_version)
			break;	/* We are done */
		prev_version= client_version;
	}
}

static void init_sksc(SHA256_CTX *dhsec_ctx)
{
	int r;
	SHA256_CTX c_ctx;
	SHA256_CTX s_ctx;
	unsigned char c_hash[SHA256_DIGEST_LENGTH];
	unsigned char s_hash[SHA256_DIGEST_LENGTH];

	c_ctx= *dhsec_ctx;
	SHA256_Update(&c_ctx, (unsigned char *)"C", 1);
	SHA256_Final(c_hash, &c_ctx);

	s_ctx= *dhsec_ctx;
	SHA256_Update(&s_ctx, (unsigned char *)"S", 1);
	SHA256_Final(s_hash, &s_ctx);

	assert(SHA256_DIGEST_LENGTH == SKSC_KEY_LENGTH);
	r= sksc_init(&sksc_c, c_hash);
	if (r != 0)
		fatal("Unable to initialize SKSC");
	r= sksc_init(&sksc_s, s_hash);
	if (r != 0)
		fatal("Unable to initialize SKSC");

	sksc_c_currsize= 0;
	sksc_c_offset= 0;

	/* Don't leak any data */
	memset(&c_ctx, '\0', sizeof(c_ctx));
	memset(&s_ctx, '\0', sizeof(s_ctx));
	memset(&c_hash, '\0', sizeof(c_hash));
	memset(&s_hash, '\0', sizeof(s_hash));
}

static void usage(void)
{
	fprintf(stderr, "Usage: sscserver [-V]\n");
	exit(1);
}


/*
 * $PchId: sscserver.c,v 1.2 2011/12/28 11:56:25 philip Exp philip $
 */
