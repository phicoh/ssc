/*
rsagen.c

Generate a RSA public/private key pair

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../lib/mp/libcrypt.h"
#include "../lib/sha2/sha2.h"
#include "../lib/rsa/rsa.h"

#define SSC_DIR		".ssc"
#define KEY_PRIV	"key-priv"
#define KEY_PUB		"key-pub"

static char *progname;

static char *concat(char *s1, char *s2);
static void fatal(char *fmt, ...);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, i, r, fd;
	int h_flag;
	char *len_str, *check, *n_str, *p_str, *priv_str, *pub_str;
	char *home, *dir;
	u8_t *buf, *cp;
	unsigned char *n_buf, *p_buf;
	unsigned len;
	FILE *priv_file, *pub_file;
	BigInt n, p;
	prnd_t prnd;
	SHA256_CTX ctx;
	u8_t hash[SHA256_DIGEST_LENGTH];
	struct stat sb;

	(progname=strrchr(argv[0],'/')) ? progname++ : (progname=argv[0]);

	h_flag= 0;
	while(c= getopt(argc, argv, "?h"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'h':
			h_flag= 1;
			break;
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	if (optind >= argc)
		usage();
	len_str= argv[optind++];

	priv_str= pub_str= NULL;	/* lint */
	if (h_flag)
	{
		home= getenv("HOME");
		if (home == NULL)
			fatal("HOME environment variable not set");
		dir= concat(home, "/" SSC_DIR);
		if (stat(dir, &sb) == -1 && errno == ENOENT)
		{
			/* Create directory */
			fprintf(stderr, "Creating directory %s\n",
				dir);
			r= mkdir(dir, 0700);
			if (r == -1)
			{
				fatal("unable to create '%s': %s",
					dir, strerror(errno));
			}
		}
		priv_str= concat(dir, "/" KEY_PRIV);
		pub_str= concat(dir, "/" KEY_PUB);
		free(dir);
	}

	if (argc-optind == 2)
	{
		priv_str= argv[optind++];
		pub_str= argv[optind++];
	}
	else if (argc-optind == 0 && h_flag)
		;	/* nothing to do */
	else
		usage();
	assert(optind == argc);

	len= strtoul(len_str, &check, 10);
	if (check[0] != '\0')
		fatal("bad value '%s'\n", len_str);
	if (len < 100)
		fatal("bad len %d, should be at least 300\n", len);

	if (strcmp(priv_str, "-") == 0)
		priv_file= stdout;
	else
	{
		/* Use open to set the right mode */
		fd= open(priv_str, O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1)
		{
			fatal("unable to create '%s': %s",
				priv_str, strerror(errno));
		}
		priv_file= fdopen(fd, "w");
		if (priv_file == NULL)
			fatal("fdopen failed: %s", strerror(errno));
	}

	if (strcmp(pub_str, "-") == 0)
		pub_file= stdout;
	else
	{
		pub_file= fopen(pub_str, "w");
		if (pub_file == NULL)
		{
			fatal("unable to create '%s': %s",
				pub_str, strerror(errno));
		}
	}

	prnd_init(&prnd, NULL, 0);

	n= bigInit(0);
	p= bigInit(0);
	rsa_rnd_key(len, &prnd, n, p);

	/* Hash public key */
	len= bigBytes(n);
	buf= os_malloc("main", len);
	bigToBuf_be(n, len, buf);

	/* Get rid of leading zeros */
	for (cp= buf; *cp == '\0' && cp < buf+len; cp++)
		;	/* No nothing */
	assert(cp < buf+len);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, cp, buf+len-cp);
	SHA256_Final(hash, &ctx);

	n_buf= os_malloc("main", bigBytes(n)*2+1);
	p_buf= os_malloc("main", bigBytes(p)*2+1);

	assert(n_buf != NULL && p_buf != NULL);

	bigsprint(n, n_buf);
	bigsprint(p, p_buf);

	/* Skip leading zeros */
	for (n_str= (char *)n_buf; n_str[0] == '0'; n_str++)
		; /* Nothing */
	for (p_str= (char *)p_buf; p_str[0] == '0'; p_str++)
		; /* Nothing */

	fprintf(pub_file, "RSA3 %s\n", n_str);
	fprintf(pub_file, "RSA3-SHA256 ");
	for (i= 0; i<SHA256_DIGEST_LENGTH; i++)
		fprintf(pub_file, "%02x", hash[i]);
	fprintf(pub_file, "\n");
	fprintf(priv_file, "RSA3-PRIV %s:%s\n", n_str, p_str);

	return 0;
}

static char *concat(char *s1, char *s2)
{
	size_t len;
	char *s;

	len= strlen(s1)+strlen(s2)+1;
	s= os_malloc("concat", len);
	strlcpy(s, s1, len);
	strlcat(s, s2, len);
	assert(strlen(s) == len-1);

	return s;
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");

	exit(1);
}

static void usage(void)
{;
	fprintf(stderr,
	"Usage: rsagen\t<modulus-length> <priv-key file> <pub-key file>\n"
		"\t\t-h <modulus-length>\n");
	exit(1);
}

/*
 * $PchId: rsagen.c,v 1.1 2005/05/13 10:02:24 philip Exp $
 */
