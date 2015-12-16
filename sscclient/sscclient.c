/*
sscclient.c

Simple Secure Connection client

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"

#include "../lib/prnd/prnd.h"
#include "../lib/sha2/sha2.h"
#include "../lib/sksc/sksc.h"
#include "../include/protocol.h"
#include "sscclient.h"

u32_t maxmsglen;

/* Add this to $HOME */
#define PRIV_KEY_PATH		"/.ssc/key-priv"
#define SERVER_KEYS_PATH	"/.ssc/server-keys"

#define PUBKEY_HASH_TAG "RSA3-SHA256"

#define TTY_DEVICE	"/dev/tty"

static char *progname;
static int tcp_fd;
static char *priv_key_path;

/* The variable alloc_insecure can get three different values: -1, 0, and 1.
 * -1 means that insecure connections are not allowed, and the client
 * aborts. 1 means that insecure connections are allowed. Finally, 0 means
 * that the user should be asked whether to continue or not.
 */
static int allow_insecure= 0;

static int opt_password= 0;	/* Default is no password */

static struct
{
	u32_t version;
} version_table[]=
{
	{ SV_VERSION_ONE },
	{ 0 }			/* end of list */
};

sksc_t sksc_c;	/* Symmetric key secure channel, from client to server. */
sksc_t sksc_s;	/* Symmetric key secure channel, from server to client. */
u8_t sksc_c_outbuf[4 + S_CPP_MAXMSGLEN + SKSC_OVERHEAD];
u8_t sksc_s_inbuf[4 + S_CPP_MAXMSGLEN + SKSC_OVERHEAD];
static u8_t sksc_s_buf[S_CPP_MAXMSGLEN];	/* Decoded results */
static size_t sksc_s_currsize, sksc_s_offset;

#if USE_TCPMUX
static void do_tcpmux(void);
#endif
static void do_version(struct sscp_version *version_msgp, SHA256_CTX *ctx);
static void do_user_service(char *user, char *service);
static void do_password(char *password);
static char *read_password(char *user, char *host);
static void access_granted(void);
static void init_sksc(SHA256_CTX *dhsec_ctx);
static int match_pub_key(char *servername, char *user,
	unsigned char pk_hash[SHA256_DIGEST_LENGTH]);
static void print_hash(unsigned char hash[SHA256_DIGEST_LENGTH]);
static void ask_insecure(void);
static void add_key(char *servername, char *user,
	unsigned char pk_hash[SHA256_DIGEST_LENGTH]);
static void do_options(char *list);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, r, host_key, user_key, remuser_nosig;
	char *servername, *servicename, *home, *user, *password;
	size_t len;
	prnd_t prnd;
	struct sscp_version version_msg;
	SHA256_CTX prot_hash_ctx, client_hash_ctx, server_hash_ctx,
		remuser_hash_ctx, dhsec_hash_ctx;
	unsigned char server_pk_hash[SHA256_DIGEST_LENGTH];
	unsigned char remuser_pk_hash[SHA256_DIGEST_LENGTH];
	int b_flag;
	char *l_arg, *o_arg;

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	b_flag= 0;
	l_arg= o_arg= NULL;
	while (c= getopt(argc, argv, "bl:o:?"), c != -1)
	{
		switch(c)
		{
		case 'b':
			b_flag= 1;
			break;
		case 'l':
			l_arg= optarg;
			break;
		case 'o':
			o_arg= optarg;
			break;
		case '?':
			usage();
		default:
			fatal("getopt failed: '%c'", c);
		}
	}
	if (optind >= argc)
		usage();
	servername= argv[optind++];

	if (optind >= argc)
		usage();
	servicename= argv[optind++];

	if (optind != argc)
		usage();

	if (o_arg)
		do_options(o_arg);

	if (opt_password && allow_insecure == 0)
	{
		/* By default passwords are allowed only over secure
		 * connections.
		 */
		allow_insecure= -1;
	}

	home= getenv("HOME");
	if (home == NULL)
		fatal("HOME environment variable not set");
	len= strlen(home)+sizeof(PRIV_KEY_PATH);
	priv_key_path= os_malloc("main", len);
	strlcpy(priv_key_path, home, len);
	strlcat(priv_key_path, PRIV_KEY_PATH, len);
	assert(strlen(priv_key_path)+1 == len);

	if (l_arg)
		user= l_arg;
	else
	{
		user= getenv("USER");
		if (user == NULL)
			fatal(
		"USER environment variable not set, should use getpwuid");
	}
	tcp_fd= tcp_connect(servername);
	if (tcp_fd == -1)
	{
		fatal("unable to connect to '%s': %s", servername,
			strerror(errno));
	}

#if USE_TCPMUX
	do_tcpmux();
#endif

	SHA256_Init(&prot_hash_ctx);
	SHA256_Init(&dhsec_hash_ctx);

	do_version(&version_msg, &prot_hash_ctx);
	prnd_init(&prnd, NULL, 0);
	do_dh(&version_msg, &prnd, &maxmsglen,
		&prot_hash_ctx, &dhsec_hash_ctx);

	client_hash_ctx= prot_hash_ctx;
	server_hash_ctx= prot_hash_ctx;
	remuser_hash_ctx= prot_hash_ctx;

	init_sksc(&dhsec_hash_ctx);

	rsa_user_sign(priv_key_path, &client_hash_ctx);

	r= rsa_server_sig(&server_hash_ctx, server_pk_hash);
	if (r < 0)
		fatal("server sent invalid signature");
	host_key= match_pub_key(servername, NULL, server_pk_hash);

	if (host_key == -1)
	{
		fprintf(stderr, "Server used wrong host key, hash = ");
		print_hash(server_pk_hash);
		fprintf(stderr, "\n");
		if (allow_insecure == 0)
			ask_insecure();
		if (allow_insecure < 0)
			shutdown_fatal("aborting insecure connection");
	}

	do_user_service(user, servicename);

	r= rsa_remuser_sig(&remuser_hash_ctx, remuser_pk_hash, &remuser_nosig);
	if (r < 0)
		fatal("remote user sent invalid signature");
	user_key= match_pub_key(servername, user, remuser_pk_hash);

	if (user_key == -1)
	{
		if (remuser_nosig)
		{
			fprintf(stderr,
			"Remote-user key is known, signature is missing.\n");
		}
		else
		{
			fprintf(stderr, "Server used wrong user key, hash = ");
			print_hash(remuser_pk_hash);
			fprintf(stderr, "\n");
		}
		if (allow_insecure == 0)
			ask_insecure();
		if (allow_insecure < 0)
			shutdown_fatal("aborting insecure connection");
	}
	if (user_key == 0 && host_key == 0)
	{
		fprintf(stderr, "Unknown remote host key, hash = ");
		print_hash(server_pk_hash);
		fprintf(stderr, "\n");
		if (!remuser_nosig)
		{
			fprintf(stderr, "Unknown remote user key, hash = ");
			print_hash(remuser_pk_hash);
			fprintf(stderr, "\n");
		}
		if (allow_insecure == 0)
			ask_insecure();
		if (allow_insecure < 0)
			shutdown_fatal("aborting insecure connection");
	}
	if (host_key == 0)
		add_key(servername, NULL, server_pk_hash);
	if (user_key == 0 && !remuser_nosig)
		add_key(servername, user, remuser_pk_hash);

	if (opt_password)
		password= read_password(user, servername);
	else
		password= NULL;

	do_password(password);

	access_granted();

	if (b_flag)
	{
		/* Tell application that we are ready */
		printf("\n");
		fflush(stdout);
	}

	do_inout(tcp_fd);

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
		r= read(tcp_fd, &p[o], size-o);
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
		r= write(tcp_fd, &p[o], size-o);
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

int sksc_s_readall(void *buf, size_t size)
{
	int r;
	u8_t len_bytes[4];
	u32_t len;

	if (sksc_s_offset >= sksc_s_currsize)
	{
		assert(sksc_s_offset == sksc_s_currsize);

		r= readall(len_bytes, sizeof(len_bytes));
		if (r == 0)
			fatal("sksc_s_readall: unexpected EOF from server");
		if (r <= 0)
		{
			if (r == 0)
				fatal(
				"sksc_s_readall: unexpected EOF from server");
			return r;
		}
		len= u32_from_be(len_bytes);
		if (len < 4)
		{
			fatal(
			"sksc_s_readall got bad length from server: %u",
				len);
		}
		len -= 4;
		if (len > maxmsglen+SKSC_OVERHEAD)
		{
			fatal("sksc_s_readall got bad length from server: %u",
				len+4);
		}
		assert(maxmsglen <= S_CPP_MAXMSGLEN);
		r= readall(sksc_s_inbuf, len);
		if (r <= 0)
		{
			if (r == 0)
				fatal(
				"sksc_s_readall: unexpected EOF from server");
			return r;
		}
		r= sksc_decrypt(&sksc_s, sksc_s_inbuf, len,
			sksc_s_buf, sizeof(sksc_s_buf));
		if (r < 0)
		{
			fprintf(stderr, 
"sksc_s_readall: sksc_decrypt failed: len = %lu, sizeof(sksc_s_buf) = %ld\n",
				(unsigned long)len,
				(unsigned long)sizeof(sksc_s_buf));
			return r;
		}
		if (r == 0)
			return r;

		sksc_s_offset= 0;
		sksc_s_currsize= r;
	}

	if (sksc_s_currsize-sksc_s_offset < size)
	{
		fatal("sksc_s_readall: read request too big %u > %u",
			size, sksc_s_currsize-sksc_s_offset);
	}
	memcpy(buf, sksc_s_buf+sksc_s_offset, size);
	
	sksc_s_offset += size;
	return size;
}

int sksc_c_writeall(void *data, size_t len)
{
	int r;

	assert(maxmsglen <= S_CPP_MAXMSGLEN);
	if (len > maxmsglen)
	{
		errno= EINVAL;
		return -1;
	}
	r= sksc_encrypt(&sksc_c, data, len, sksc_c_outbuf+4,
		sizeof(sksc_c_outbuf)-4);
	if (r < len)
		fatal("sksc_encrypt failed");
	u32_to_be(r+4, sksc_c_outbuf);
	r= writeall(sksc_c_outbuf, r+4);
	return r;
}

char *read_line(FILE *file)
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
					free(line);
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

void u16_to_be(U16_t v, u8_t buf[2])
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

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(1);
}

void shutdown_fatal(char *fmt, ...)
{
	va_list ap;

	/* First report the error */
	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	/* and then try to shutdown the connection */
	tcp_shutdown(tcp_fd);

	exit(1);
}

#if USE_TCPMUX
static void do_tcpmux(void)
{
	char *proto;
	ssize_t r;
	int i, got_cr;
	char c;
	char line[1024];

	proto= SSC_PROTO_NAME "\r\n";
	r= writeall(proto, strlen(proto));
	if (r <= 0)
		fatal("writeall failed: %s", strerror(errno));

	/* Do we need a timer? */

	r= readall(&c, 1);
	if (r <= 0)
	{
		fatal("error reading tcpmux reply: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	if (c == '+')
	{
		/* Eat remainder of message */
		got_cr= 0;
		for(;;)
		{
			r= readall(&c, 1);
			if (r <= 0)
			{
				fatal("error reading tcpmux reply: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			if (c == '\n' && got_cr)
				break;
			if (c == '\r')
				got_cr= 1;
		}
	}
	else
	{
		for (i= 0; i<sizeof(line)-1; i++)
		{
			r= readall(&c, 1);
			if (r <= 0)
			{
				fatal("error reading tcpmux reply: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			if (c == '\r' || c == '\n')
				break;
			if ((c < ' ' && c != '\t') || c > '~')
				c= '?';
			line[i]= c;
		}
		fatal("tcpmux service returned error: '%.*s'",
			i, line);
	}

}
#endif

static void do_version(struct sscp_version *version_msgp, SHA256_CTX *ctx)
{
	int i, r;
	struct sscp_version version_msg;
	u32_t v, best, prev_version, server_version;

	/* Start consitency check with the highest possible version number */
	prev_version= 0xffffffff;

	for (;;)
	{
		/* Negotiate a protocol version number with the server. */
		r= readall(&version_msg, sizeof(version_msg));
		if (r <= 0)
		{
			fatal("error reading version message from server: %s",
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
		server_version= u32_from_be(version_msg.sv_version);
		if (server_version == SV_VERSION_ERROR)
			shutdown_fatal("server sent error version");

		/* Consistency check. The server's version number should
		 * be less then or equal to prev_version.
		 */
		if (server_version > prev_version)
		{
			shutdown_fatal(
			"server sent bad version number (0x%x) (>= 0x%x)",
				server_version, prev_version);
		}

		/* Find the highest version we support that is less than
		 * or equal to the server's version.
		 */
		best= SV_VERSION_ERROR;
		for (i= 0; version_table[i].version != 0; i++)
		{
			v= version_table[i].version;
			if (v > server_version)
				continue;	/* Not supported by server */
			if (v < best)
				continue;	/* Not the highest */
			best= v;
		}

		/* Send the new version number. No need to initialize
		 * sv_label
		 */
		u32_to_be(best, version_msg.sv_version);

		if (best == server_version)
		{
			/* Combine this message with the next one. */
			*version_msgp= version_msg;
			break;
		}

		SHA256_Update(ctx, (unsigned char *)&version_msg,
			sizeof(version_msg));
		r= writeall(&version_msg, sizeof(version_msg));
		if (r <= 0)
		{
			fatal("error sending version message to server: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}

		if (best == SV_VERSION_ERROR)
		{
			shutdown_fatal(
			"cannot find version to match server's version 0x%x",
				server_version);
		}
		prev_version= best;
	}
}

static void do_user_service(char *user, char *service)
{
	u16_t len1, len2, pad;
	size_t totlen;
	int r;
	u8_t *ucp;
	void *msgp;
	struct sscp_crusr *crusr;

	/* Send message to server */
	len1= strlen(user);
	len2= strlen(service);

	totlen= sizeof(*crusr) + 2+len1 + 2+len2;
	if (totlen < 128)
	{
		/* Hide the length of the user and service names */
		pad= 128-totlen;
	}
	else
		pad= 1;
	totlen += pad;

	msgp= os_malloc("do_user_service", totlen);
	crusr= msgp;
	u16_to_be(totlen, crusr->sc_len);
	u16_to_be(S_CRUSR_TYPE, crusr->sc_type);

	/* Start of the first string */
	ucp= (u8_t *)(crusr+1);

	/* Remote user name */
	u16_to_be(len1, ucp);
	ucp += 2;
	memcpy(ucp, user, len1);
	ucp += len1;

	/* Service */
	u16_to_be(len2, ucp);
	ucp += 2;
	memcpy(ucp, service, len2);
	ucp += len2;

	/* Padding */
	memset(ucp, '\0', pad);
	ucp += pad;

	assert(ucp == (u8_t *)msgp+totlen);

	r= sksc_c_writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending user/service message to server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	free(msgp);
}

static void do_password(char *password)
{
	u16_t len1, pad;
	size_t totlen;
	int r;
	u8_t *ucp;
	void *msgp;
	struct sscp_password *pwmsg;

	/* Send message to server */
	len1= (password != NULL) ? strlen(password) : 0;

	totlen= sizeof(*pwmsg) + 2+len1;
	if (totlen < 128)
	{
		/* Hide the length of the password (and whether a password
		 * is present at all.
		 */
		pad= 128-totlen;
	}
	else
		pad= 1;
	totlen += pad;

	msgp= os_malloc("do_password", totlen);
	pwmsg= msgp;
	u16_to_be(totlen, pwmsg->sp_len);
	u16_to_be(S_PASSWORD_TYPE, pwmsg->sp_type);
	u16_to_be((password == NULL) ? S_PASSWORD_F_INVALID : 0 ,
		pwmsg->sp_flags);

	/* Start of the string */
	ucp= (u8_t *)(pwmsg+1);

	/* password */
	u16_to_be(len1, ucp);
	ucp += 2;
	if (len1 != 0)
		memcpy(ucp, password, len1);
	ucp += len1;

	/* Padding */
	memset(ucp, '\0', pad);
	ucp += pad;

	assert(ucp == (u8_t *)msgp+totlen);

	r= sksc_c_writeall(msgp, totlen);
	if (r <= 0)
	{
		fatal("error sending password message to server: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	free(msgp);
}

static char *read_password(char *user, char *host)
{
	static char line[1024];

	int t_errno;
	char *l, *cp;
	FILE *file;

	file= fopen(TTY_DEVICE, "r+");
	if (file == NULL)
		fatal("unable to open '%s': %s", TTY_DEVICE, strerror(errno));
	set_echo(file, 0 /* off */);

	fprintf(file, "Enter password for %s@%s: ", user, host);

	l= fgets(line, sizeof(line), file);
	t_errno= errno;

	fprintf(file, "\n");

	set_echo(file, 1 /* on */);

	if (l == NULL)
	{
		fatal("unable to read password from %s: %s",
			feof(file) ? "end of file" : strerror(t_errno));
	}

	cp= strchr(line, '\n');
	if (cp)
		*cp = '\0';

	fclose(file);

	return line;
}

static void access_granted(void)
{
	int r;
	u16_t len, type, flags, extra_len;
	u8_t *extra;
	struct sscp_as as_msg;

	r= sksc_s_readall(&as_msg, sizeof(as_msg));
	if (r <= 0)
	{
		fatal("error reading access message from server: %s",
			r < 0 ? strerror(errno) :
			"unexpected end of file");
	}

	len= u16_from_be(as_msg.sa_len);
	type= u16_from_be(as_msg.sa_type);
	flags= u16_from_be(as_msg.sa_flags);

	if (type != S_AS_TYPE)
		shutdown_fatal("bad type in access message: %u", type);
	if (len < sizeof(as_msg))
		shutdown_fatal("bad length in access message: %u", len);
	extra_len= len-sizeof(as_msg);
	if (extra_len)
	{
		/* Padding is allow here but pointless */
		extra= os_malloc("access_granted", extra_len);
		r= sksc_s_readall(extra, extra_len);
		if (r <= 0)
		{
			fatal("error reading access message from server: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}
		free(extra);
	}

	if (flags & S_AS_F_DENIED)
		fatal("server denied access.");
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
	sksc_s_currsize= 0;
	sksc_s_offset= 0;

	/* Don't leak any data */
	memset(&c_ctx, '\0', sizeof(c_ctx));
	memset(&s_ctx, '\0', sizeof(s_ctx));
	memset(&c_hash, '\0', sizeof(c_hash));
	memset(&s_hash, '\0', sizeof(s_hash));
}

static int match_pub_key(char *servername, char *user,
	unsigned char pk_hash[SHA256_DIGEST_LENGTH])
{
	char *home, *server_keys_path, *key_buf, *key, *line;
	char c1, c2, *cp, *cp1;
	int i, match, v1, v2;
	size_t len, name_len, tag_len;
	FILE *file;
	unsigned char file_hash[SHA256_DIGEST_LENGTH];

	/* Server keys file path */
	home= getenv("HOME");
	if (home == NULL)
		fatal("HOME environment variable not set");
	len= strlen(home)+sizeof(SERVER_KEYS_PATH);
	server_keys_path= os_malloc("match_pub_key", len);
	strlcpy(server_keys_path, home, len);
	strlcat(server_keys_path, SERVER_KEYS_PATH, len);
	assert(strlen(server_keys_path)+1 == len);

	/* Target */
	if (user != NULL)
	{
		len= strlen(user) + 1 + strlen(servername) + 1;
		key_buf= os_malloc("match_pub_key", len);
		strlcpy(key_buf, user, len);
		strlcat(key_buf, "@", len);
		strlcat(key_buf, servername, len);
		assert(strlen(key_buf) == len-1);
		key= key_buf;
	}
	else
	{
		key_buf= NULL;
		key= servername;
	}
	name_len= strlen(key);
	tag_len= strlen(PUBKEY_HASH_TAG);
	
	file= fopen(server_keys_path, "r");
	if (file == NULL)
	{
		free(server_keys_path);
		free(key_buf);
		return 0;
	}

	match= 0;
	for (;;)
	{
		line= read_line(file);
		if (line == NULL)
			break;

		cp= line;

		/* Skip leading white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		if (cp[0] == '#')
		{
			/* Comment line */
			free(line);
			continue;
		}

		/* Get key name */
		cp1= cp;
		while (*cp1 != '\0' && *cp1 != ' ' && *cp1 != '\t')
			cp1++;
		if (cp1-cp != name_len || strncmp(cp, key, name_len) != 0)
		{
			/* No match */
			free(line);
			continue;
		}

		cp= cp1;

		/* Skip white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		/* Get tag name */
		cp1= cp;
		while (*cp1 != '\0' && *cp1 != ' ' && *cp1 != '\t')
			cp1++;
		if (cp1-cp != tag_len ||
			strncmp(cp, PUBKEY_HASH_TAG, tag_len) != 0)
		{
			/* No match */
			free(line);
			continue;
		}

		cp= cp1;

		/* Skip white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		/* Get hash */
		c1= c2= 0;
		for (i= 0; i<SHA256_DIGEST_LENGTH; i++)
		{
			c1= cp[2*i];
			if (c1 != '\0')
				c2= cp[2*i+1];
			if (c1 == '\0' || c2 == '\0')
			{
				fatal(
			"bad line in server keys file (too short): %s",
					line);
			}
			if (c1 >= '0' && c1 <= '9')
				v1= c1-'0';
			else if (c1 >= 'A' && c1 <= 'F')
				v1= c1-'A' + 10;
			else if (c1 >= 'a' && c1 <= 'f')
				v1= c1-'a' + 10;
			else
				v1= -1;
			if (c2 >= '0' && c2 <= '9')
				v2= c2-'0';
			else if (c2 >= 'A' && c2 <= 'F')
				v2= c2-'A' + 10;
			else if (c2 >= 'a' && c2 <= 'f')
				v2= c2-'a' + 10;
			else
				v2= -1;
			if (v1 == -1 || v2 == -1)
			{
				fatal(
			"bad line in server keys file (bad hex digit): %s",
					line);
			}
			file_hash[i]= ((v1 << 4) | v2);
		}

		/* Skip hash */
		cp += 2*i;

		/* Skip white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		if (*cp != '\0')
		{
			fatal(
			"bad line in server keys file (garbage at end): %s",
				line);
		}

		if (memcmp(file_hash, pk_hash, SHA256_DIGEST_LENGTH) == 0)
			match= 1;
		else
			match= -1;
		break;
	}
	fclose(file);
	free(server_keys_path);
	free(key_buf);
	return match;
}

static void print_hash(unsigned char hash[SHA256_DIGEST_LENGTH])
{
	int i;

	for (i= 0; i<SHA256_DIGEST_LENGTH; i++)
		fprintf(stderr, "%02x", hash[i]);
}

static void ask_insecure(void)
{
	FILE *file;
	char buf[80];

	file= fopen(TTY_DEVICE, "r+");
	if (file == NULL)
		fatal("unable to open '%s': %s", TTY_DEVICE, strerror(errno));
	fprintf(file,
		"Do you want to abort this (insecure) connection? [yes]/no: ");
	fflush(file);
	for (;;)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			fatal("error reading from %s: %s",
				TTY_DEVICE, feof(file) ? "end of file" :
				strerror(errno));
		}
		if (strcmp(buf, "\n") == 0 || strcmp(buf, "yes\n") == 0)
		{
			allow_insecure= -1;
			break;
		}
		if (strcmp(buf, "no\n") == 0)
		{
			allow_insecure= 1;
			break;
		}
		fprintf(file, "please enter yes or no: ");
		fflush(file);
	}
	fclose(file);
}

static void add_key(char *servername, char *user,
	unsigned char pk_hash[SHA256_DIGEST_LENGTH])
{
	int i, r;
	char *home, *server_keys_path;
	size_t len;
	FILE *file;
	char buf[80];

	file= fopen(TTY_DEVICE, "r+");
	if (file == NULL)
		fatal("unable to open '%s': %s", TTY_DEVICE, strerror(errno));
	fprintf(file,
		"Do you want to add a key for '%s%s%s'? [no]/yes: ",
			user ? user : "",
			user ? "@" : "",
			servername);
	fflush(file);
	for (;;)
	{
		if (fgets(buf, sizeof(buf), file) == NULL)
		{
			fatal("error reading from %s: %s",
				TTY_DEVICE, feof(file) ? "end of file" :
				strerror(errno));
		}
		if (strcmp(buf, "\n") == 0 || strcmp(buf, "no\n") == 0)
		{
			fclose(file);
			return;
		}
		if (strcmp(buf, "yes\n") == 0)
			break;
		fprintf(file, "please enter yes or no: ");
		fflush(file);
	}
	fclose(file);

	/* Server keys file path */
	home= getenv("HOME");
	if (home == NULL)
		fatal("HOME environment variable not set");
	len= strlen(home)+sizeof(SERVER_KEYS_PATH);
	server_keys_path= os_malloc("add_key", len);
	if (server_keys_path == NULL)
		fatal("unable to allocate %u bytes", len);
	strlcpy(server_keys_path, home, len);
	strlcat(server_keys_path, SERVER_KEYS_PATH, len);
	assert(strlen(server_keys_path)+1 == len);

	file= fopen(server_keys_path, "a");
	if (file == NULL)
	{
		fatal("unable to open '%s': %s", server_keys_path,
			strerror(errno));
	}

	if (user)
	{
		r= fprintf(file, "%s@", user);
		if (r < 0)
			fatal("error writing to '%s'", server_keys_path);
	}
	r= fprintf(file, "%s %s ", servername, PUBKEY_HASH_TAG);
	if (r < 0)
		fatal("error writing to '%s'", server_keys_path);
	for (i= 0; i<SHA256_DIGEST_LENGTH; i++)
	{
		r= fprintf(file, "%02x", pk_hash[i]);
		if (r < 0)
			fatal("error writing to '%s'", server_keys_path);
	}
	r= fprintf(file, "\n");
	if (r < 0)
		fatal("error writing to '%s'", server_keys_path);

	free(server_keys_path);
	fclose(file);
}

static void do_options(char *list)
{
	char *cp, *cp1;
	size_t len;

	cp= list;
	for(;;)
	{
		cp1= cp;
		while (*cp1 != '\0' && *cp1 != ',')
			cp1++;
		len= cp1-cp;
		if (len == 0)
			fatal("bad option string '%s'", list);
		if (strncmp(cp, "password", len) == 0 &&
			len == strlen("password"))
		{
			opt_password= 1;
		}
		else if (strncmp(cp, "insecure", len) == 0 &&
			len == strlen("insecure"))
		{
			allow_insecure= 1;
		}
		else
			fatal("bad option in option list: '%.*s'", len, cp);
		if (*cp1 == '\0')
			break;
		cp= cp1+1;
	}
}

static void usage(void)
{
	fprintf(stderr,
"Usage: sscclient [-b] [-l <rem-user>] [-o <options>] <hostname> <service>\n");
	exit(1);
}


/*
 * $PchId: sscclient.c,v 1.4 2011/12/29 20:33:20 philip Exp $
 */
