/*
sscrcp.c

Copy files to or from a remote system using a secure channel

Created:	March 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/prot_rcp.h"
#include "../include/sscversion.h"
#include "sscrcp.h"

#define SSCCLIENT_PATH	"/usr/local/sbin/sscclient"

#define SERVICE "rcp"

#define N_ARGS		9

/* All mode bits */
#define S_MODEMASK (S_ISUID|S_ISGID|S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

static char *progname;
static int p_in, p_out;
static pid_t client_pid;
static int p_flag;
static char *options;
struct
{
	struct sscrcp_hdr hdr;
	char buf[16*1024];
} data_msg;

static int do_interactive(char *userhost);
static int to_remote(int argc, char *argv[]);
static int send_file(char *src, char *dst, int dodir);
static int from_remote(char *src, char *dst);
static int get_multi(char *user, char *hostname, char *rempath, char *dst);
static int get_file(char *src, char *dst);
static void do_quit(void);
static char *get_mode(char *fn, mode_t *modep);
static char *get_times(char *fn, time_t *atimep, time_t *mtimep);
static char *set_mode(char *fn, mode_t mode);
static char *set_times(char *fn, time_t atime, time_t mtime);
static int isRemote(char *str);
static void cancel_sink(struct sscrcp_hdr *hdrp);
static void start_client(char *hostname, char *user, char *options);
static void read_greeting(void);
static void send_cmd_fn(u16_t cmd, char *str);
static void send_error(char *str);
static void send_ok(void);
static char *get_status(struct sscrcp_hdr *hdrp);
static void pretty(char *str);
static char *dupstr(char *str);
static char *concat3(char *str1, char *str2, char *str3);
static int wildcard(char *str);
static int readall(void *buf, size_t size);
static int writeall(void *buf, size_t size);
static int fd_writeall(int fd, void *buf, size_t size);
static void u16_to_be(u16_t v, u8_t buf[2]);
static void u32_to_be(u32_t v, u8_t buf[4]);
static u16_t u16_from_be(u8_t buf[2]);
static u32_t u32_from_be(u8_t buf[4]);
static void error(char *fmt, ...);
static void fatal(char *fmt, ...);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, r;
	char *o_arg;

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	p_flag= 0;
	o_arg= NULL;
	while (c=getopt(argc, argv, "?o:pV"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'o':
			o_arg= optarg;
			break;
		case 'p':
			p_flag= 1;
			break;
		case 'V':
			fatal("version %s", sscversion);
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	options= o_arg;

	if (optind == argc)
		usage();
	r= 0;	/* LINT */
	if (argc == optind+1)
		r= do_interactive(argv[optind]);
	else if (isRemote(argv[argc-1]))
		r= to_remote(argc-optind, &argv[optind]);
	else if (isRemote(argv[optind]) && argc == optind+2)
		r= from_remote(argv[optind], argv[optind+1]);
	else
		usage();
	return r;
}

static int do_interactive(char *userhost)
{
	fatal("do_interactive: not implemented");
	exit(1);	/* lint */
}

static int to_remote(int argc, char *argv[])
{
	int i, failed, dodir;
	char *cp, *odst, *dst;
	char *user, *hostname, *rempath;

	odst= argv[argc-1];
	dst= dupstr(odst);

	/* Parse remote path */
	cp= strchr(dst, ':');
	assert(cp != NULL);
	*cp= '\0';
	rempath= cp+1;
	if (strlen(rempath) == 0)
		fatal("bad remote path '%s'", odst);
	cp= strchr(dst, '@');
	if (cp != NULL && cp < rempath)
	{
		*cp= '\0';
		hostname= cp+1;
		user= dst;
	}
	else
	{
		hostname= dst;
		user= NULL;
	}
	if (strlen(hostname) == 0)
		fatal("bad host name in '%s': '%s'", odst, hostname);
	if (user != NULL && strlen(user) == 0)
		fatal("bad user name in '%s': '%s'", odst, user);

	start_client(hostname, user, options);
	read_greeting();

	failed= 0;
	dodir= (argc > 2);	/* Target must be a directory if multiple
				 * files are copied.
				 */
	for (i= 0; i<argc-1; i++)
		failed |= send_file(argv[i], rempath, dodir);

	free(dst);

	do_quit();

	return failed;
}

static int send_file(char *src, char *dst, int dodir)
{
	int fd, failed, t_errno;
	u16_t len, type;
	ssize_t r;
	char *cp, *actdst, *str;
	struct sscrcp_hdr hdr, *hdrp;
	struct stat sb;

	/* Open source file */
	fd= open(src, O_RDONLY);
	if (fd == -1)
	{
		error("unable to open '%s': %s", src, strerror(errno));
		return 1;
	}

	/* Assume that the target is a directory */
	cp= strrchr(src, '/');
	if (cp == NULL)
		cp= src;
	else
		cp++;
	actdst= concat3(dst, "/", cp);

	send_cmd_fn(SSCRCP_PUT, actdst);
	str= get_status(NULL);
	if (str != NULL && !dodir)
	{
		/* Try just dst */
		free(actdst);
		actdst= dupstr(dst);
		send_cmd_fn(SSCRCP_PUT, actdst);
		str= get_status(NULL);
	}
	if (str)
	{
		error("server does not accept '%s': %s", actdst, str);
		free(actdst);
		close(fd);
		return 1;
	}

	/* Copy loop */
	for (;;)
	{
		r= read(fd, data_msg.buf, sizeof(data_msg.buf));
		if (r <= 0)
			break;
		len= sizeof(data_msg.hdr)+r;
		u16_to_be(len, data_msg.hdr.srh_len);
		u16_to_be(SSCRCP_CDATA, data_msg.hdr.srh_type);
		r= writeall(&data_msg, len);
		if (r <= 0)
		{
			fatal("write failed: %s",
				r == 0 ? "EOF" : strerror(errno));
		}
	}

	t_errno= errno;
	if (fstat(fd, &sb) == -1)
		fatal("fstat failed: %s", strerror(errno));
	close(fd);
	
	failed= 0;
	if (r == 0)
	{
		send_ok();
	}
	else
	{
		error("error reading from '%s': %s", src, strerror(t_errno));
		send_error(strerror(t_errno));
		failed= 1;
	}

	/* Look for cancel message */
	r= readall(&hdr, sizeof(hdr));
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	type= u16_from_be(hdr.srh_type);
	if (type == SSCRCP_SCANCEL)
		hdrp= NULL;	/* Ignore cancel message and get new header */
	else
		hdrp= &hdr;

	str= get_status(hdrp);
	if (str)
	{
		if (!failed)
		{
			error("error sending to '%s': %s",
				actdst, str);
		}
		free(str);
		failed= 1;
	}

	if (!failed)
	{
		str= set_mode(actdst, sb.st_mode);
		if (str)
		{
			error("error setting mode of '%s': %s", actdst, str);
			free(str);
			failed= 1;
		}
	}
	if (!failed && p_flag)
	{
		str= set_times(actdst, sb.st_atime, sb.st_mtime);
		if (str)
		{
			error("error setting times on '%s': %s", actdst, str);
			free(str);
			failed= 1;
		}
	}

	free(actdst);
	return failed;
}

static int from_remote(char *src, char *dst)
{
	int r, failed;
	char *cp;
	char *user, *hostname, *rempath;
	struct stat sb;

	src= dupstr(src);

	/* Parse remote path */
	cp= strchr(src, ':');
	assert(cp != NULL);
	*cp= '\0';
	rempath= cp+1;
	if (strlen(rempath) == 0)
		fatal("bad remote path '%s'", src);
	cp= strchr(src, '@');
	if (cp != NULL && cp < rempath)
	{
		*cp= '\0';
		hostname= cp+1;
		user= src;
	}
	else
	{
		hostname= src;
		user= NULL;
	}
	if (strlen(hostname) == 0)
		fatal("bad host name in '%s': '%s'", src, hostname);
	if (user != NULL && strlen(user) == 0)
		fatal("bad user name in '%s': '%s'", src, user);

	/* Look for wildcards */
	cp= strrchr(rempath, '/');
	if (cp == NULL)
		cp= rempath;
	if (wildcard(cp))
	{
		r= get_multi(user, hostname, rempath, dst);
		return r;
	}

	r= stat(dst, &sb);
	if (r == 0 && S_ISDIR(sb.st_mode))
	{
		/* Target is a directory, try to concat the last part of
		 * the source.
		 */
		cp= strrchr(rempath, '/');
		if (cp == NULL)
			cp= rempath;
		else
			cp++;

		/* Additional error checks? */
		dst= concat3(dst, "/", cp);
	}
	else
		dst= dupstr(dst);

	start_client(hostname, user, options);
	read_greeting();

	failed= get_file(rempath, dst);

	free(src);
	free(dst);

	do_quit();

	return failed;
}

static int get_multi(char *user, char *hostname, char *rempath, char *dst)
{
	int i, r, failed;
	size_t list_max, list_curr;
	u16_t len, type;
	char *cp, *str, *pattern;
	char **list;
	char *remdir, *srcfile, *dstfile;
	struct sscrcp_hdr hdr;
	struct stat sb;

	r= stat(dst, &sb);
	if (r == -1)
	{
		fatal("unable to stat '%s': %s", dst, strerror(errno));
	}
	if (!S_ISDIR(sb.st_mode))
	{
		/* Target is not a directory */
		fatal("'%s' is not a directory", dst);
	}

	if (user)
		fatal("from_remote: user not supported");
	start_client(hostname, user, options);
	read_greeting();

	/* Extract directory name */
	cp= strrchr(rempath, '/');
	if (cp != NULL)
	{
		remdir= dupstr(rempath);
		*strrchr(remdir, '/')= '\0';
	}
	else
		remdir= dupstr(".");

	pattern= strrchr(rempath, '/');
	if (pattern == NULL)
		pattern= rempath;
	else
		pattern++;

	send_cmd_fn(SSCRCP_LISTDIR, remdir);
	list_curr= 0;
	list_max= 10;
	list= os_malloc("get_multi", list_max * sizeof(*list));
	for (;;)
	{
		r= readall(&hdr, sizeof(hdr));
		if (r <= 0)
		{
			fatal("error reading reply: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		type= u16_from_be(hdr.srh_type);
		len= u16_from_be(hdr.srh_len);
		if (type != SSCRCP_DIRENTRY)
			break;

		if (len < sizeof(hdr))
		{
			fatal("bad length %d in message type %d",
				len, type);
		}
		len -= sizeof(hdr);
		str= os_malloc("get_multi", len+1);
		r= readall(str, len);
		if (r <= 0)
		{
			fatal("error reading reply: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		str[len]= '\0';
		if (!smatch(str, pattern))
			continue;
		if (list_curr == list_max)
		{
			list_max *= 2;
			list= realloc(list, list_max * sizeof(*list));
			if (list == NULL)
			{
				fatal("unable to allocate %u bytes",
					list_max * sizeof(*list));
			}
		}
		list[list_curr]= str;
		list_curr++;
	}
	str= get_status(&hdr);
	if (str)
	{
		fatal("unable to list '%s' at server '%s': %s",
			remdir, hostname, str);
	}

	failed= 0;
	if (list_curr == 0)
	{
		/* Special case, no files match the pattern. Try the get
		 * the pattern itself.
		 */
		srcfile= concat3(remdir, "/", pattern);
		dstfile= concat3(dst, "/", pattern);
		failed |= get_file(srcfile, dstfile);

		free(srcfile);
		free(dstfile);
	}
	for (i= 0; i<list_curr; i++)
	{
		srcfile= concat3(remdir, "/", list[i]);
		dstfile= concat3(dst, "/", list[i]);
		failed |= get_file(srcfile, dstfile);

		free(srcfile);
		free(dstfile);
		free(list[i]);
	}
	
	free(remdir);
	free(list);
	return failed;
}

static int get_file(char *src, char *dst)
{
	int r, fd;
	u16_t type, len;
	size_t n, o;
	mode_t mode;
	time_t atime, mtime;
	char *str;
	struct sscrcp_hdr hdr;
	struct utimbuf ub;

	send_cmd_fn(SSCRCP_GET, src);
	str= get_status(NULL);
	if (str)
	{
		error("unable to get '%s': %s", src, str);
		return 1;
	}

	/* Try to create output file */
	fd= open(dst, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd == -1)
	{
		error("unable to create '%s': %s", dst, strerror(errno));
		cancel_sink(&hdr);
		type= u16_from_be(hdr.srh_type);
	}
	else
	{
		/* Copy loop */
		for(;;)
		{
			r= readall(&hdr, sizeof(hdr));
			if (r <= 0)
			{
				fatal("error reading reply: %s",
					r == 0 ? "unexpected EOF" :
					strerror(errno));
			}
			type= u16_from_be(hdr.srh_type);
			len= u16_from_be(hdr.srh_len);
			if (type != SSCRCP_SDATA)
				break;

			if (len < sizeof(hdr))
			{
				fatal("bad length %d in message type %d",
					len, type);
			}
			len -= sizeof(hdr);
			for (o= 0; o<len; o += n)
			{
				n= len-o;
				if (n > sizeof(data_msg.buf))
					n= sizeof(data_msg.buf);
				r= readall(data_msg.buf, n);
				if (r <= 0)
				{
					fatal("error reading reply: %s",
						r == 0 ? "unexpected EOF" :
						strerror(errno));
				}

				r= fd_writeall(fd, data_msg.buf, r);
				if (r <= 0)
				{
					/* XXX */
					fatal("error writing to %s: %s",
						dst,
						r == 0 ? "unexpected EOF" :
						strerror(errno));
				}
			}
		}
		close(fd);
	}

	if (type == SSCRCP_SOK)
		;	/* OK */
	else if (type == SSCRCP_SERROR)
	{
		str= get_status(&hdr);

		/* Reset times */
		ub.actime= 0;
		ub.modtime= 0;
		(void) utime(dst, &ub);

		error("unable to get '%s': %s\n", src, str);
		return 1;
	}
	else
		fatal("bad message type %d", type);

	str= get_mode(src, &mode);
	if (str)
	{
		error("unable to get mode of '%s': %s\n", src, str);
		return 1;
	}
	r= chmod(dst, mode & S_MODEMASK);
	if (r != 0)
	{
		error("chmod failed for '%s': %s", dst, strerror(errno));
		return 1;
	}

	if (p_flag)
	{
		str= get_times(src, &atime, &mtime);
		if (str)
		{
			error("unable to get times of '%s': %s\n",
				src, str);
			return 1;
		}
		ub.actime= atime;
		ub.modtime= mtime;
		r= utime(dst, &ub);
		if (r != 0)
		{
			error("utime %s failed: %s", dst, strerror(errno));
			return 1;
		}
	}
	return 0;
}

static void do_quit(void)
{
	int r;
	u16_t len;
	char *str;
	struct sscrcp_hdr hdr;

	len= sizeof(hdr);
	u16_to_be(len, hdr.srh_len);
	u16_to_be(SSCRCP_QUIT, hdr.srh_type);

	r= writeall(&hdr, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));

	str= get_status(NULL);
	if (str)
		fatal("quit failed: %s", str);
}

static char *get_mode(char *fn, mode_t *modep)
{
	int r;
	size_t offset;
	u16_t len, type;
	char *str, *cp;
	struct sscrcp_hdr hdr;
	struct sscrcp_mode_repl repl;

	send_cmd_fn(SSCRCP_GETMODE, fn);

	r= readall(&hdr, sizeof(hdr));
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	type= u16_from_be(hdr.srh_type);
	if (type == SSCRCP_SERROR)
	{
		str= get_status(&hdr);
		assert(str != NULL);
		return str;
	}
	if (type != SSCRCP_MODE_REPL)
		fatal("get_mode: bad message type %d", type);

	len= u16_from_be(hdr.srh_len);
	if (len != sizeof(repl))
		fatal("bad length for mode reply message: %d", len);

	/* Copy prefix */
	memcpy(&repl, &hdr, sizeof(hdr));

	/* Get the rest of the message */
	offset= sizeof(hdr);
	cp= (char *)&repl;
	r= readall(&cp[offset], len-offset);
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	*modep= u16_from_be(repl.srmr_mode);

	return NULL;
}

static char *get_times(char *fn, time_t *atimep, time_t *mtimep)
{
	int r;
	size_t offset;
	u16_t len, type;
	time_t t_a_hi, t_a, t_m_hi, t_m;
	char *str, *cp;
	struct sscrcp_hdr hdr;
	struct sscrcp_times_repl repl;

	send_cmd_fn(SSCRCP_GETTIMES, fn);

	r= readall(&hdr, sizeof(hdr));
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	type= u16_from_be(hdr.srh_type);
	if (type == SSCRCP_SERROR)
	{
		str= get_status(&hdr);
		assert(str != NULL);
		return str;
	}
	if (type != SSCRCP_TIMES_REPL)
		fatal("get_times: bad message type %d", type);

	len= u16_from_be(hdr.srh_len);
	if (len != sizeof(repl))
		fatal("bad length for mode reply message: %d", len);

	/* Copy prefix */
	memcpy(&repl, &hdr, sizeof(hdr));

	/* Get the rest of the message */
	offset= sizeof(hdr);
	cp= (char *)&repl;
	r= readall(&cp[offset], len-offset);
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	t_a_hi= u32_from_be(repl.srtr_atime_high);
	t_a= u32_from_be(repl.srtr_atime_low);
	t_m_hi= u32_from_be(repl.srtr_mtime_high);
	t_m= u32_from_be(repl.srtr_mtime_low);

	if (t_a_hi != 0 || t_m_hi != 0)
		return "timestamp out of range";

	*atimep= t_a;
	*mtimep= t_m;

	return NULL;
}

static char *set_mode(char *fn, mode_t mode)
{
	int r;
	size_t slen;
	u16_t len;
	void *buf;
	char *str, *cp;
	struct sscrcp_setmode *hdrp;

	slen= strlen(fn);
	len= sizeof(*hdrp) + slen;
	buf= os_malloc("set_mode", len);
	hdrp= buf;
	cp= (char *)&hdrp[1];
	memcpy(cp, fn, slen);

	u16_to_be(len, hdrp->srsm_len);
	u16_to_be(SSCRCP_SETMODE, hdrp->srsm_type);
	u16_to_be(mode, hdrp->srsm_mode);

	r= writeall(hdrp, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));

	str= get_status(NULL);
	return str;
}

static char *set_times(char *fn, time_t atime, time_t mtime)
{
	int r;
	size_t slen;
	u16_t len;
	void *buf;
	char *str, *cp;
	struct sscrcp_settimes *hdrp;

	slen= strlen(fn);
	len= sizeof(*hdrp) + slen;
	buf= os_malloc("set_times", len);
	hdrp= buf;
	cp= (char *)&hdrp[1];
	memcpy(cp, fn, slen);

	u16_to_be(len, hdrp->srst_len);
	u16_to_be(SSCRCP_SETTIMES, hdrp->srst_type);
	u32_to_be(0, hdrp->srst_atime_high);
	u32_to_be(atime, hdrp->srst_atime_low);
	u32_to_be(0, hdrp->srst_atime_frac);
	u32_to_be(0, hdrp->srst_mtime_high);
	u32_to_be(mtime, hdrp->srst_mtime_low);
	u32_to_be(0, hdrp->srst_mtime_frac);

	r= writeall(hdrp, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));

	str= get_status(NULL);
	return str;
}

static int isRemote(char *str)
{
	return (strchr(str, ':') != NULL);
}

static void cancel_sink(struct sscrcp_hdr *hdrp)
{
	u16_t len, type;
	size_t n, o;
	int r;
	struct sscrcp_hdr hdr;

	len= sizeof(hdr);
	u16_to_be(len, hdr.srh_len);
	u16_to_be(SSCRCP_CCANCEL, hdr.srh_type);

	r= writeall(&hdr, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));

	/* discard loop */
	for(;;)
	{
		r= readall(hdrp, sizeof(*hdrp));
		if (r <= 0)
		{
			fatal("error reading message: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		type= u16_from_be(hdrp->srh_type);
		len= u16_from_be(hdrp->srh_len);
		if (type != SSCRCP_SDATA)
			break;

		if (len < sizeof(*hdrp))
		{
			fatal("bad length %d in message type %d",
				len, type);
		}
		len -= sizeof(*hdrp);
		for (o= 0; o<len; o += n)
		{
			n= len-o;
			if (n > sizeof(data_msg.buf))
				n= sizeof(data_msg.buf);
			r= readall(data_msg.buf, n);
			if (r <= 0)
			{
				fatal("error reading data: %s",
					r == 0 ? "unexpected EOF" :
					strerror(errno));
			}

		}
	}
}


static void start_client(char *hostname, char *user, char *options)
{
	int i, r, fds_in[2], fds_out[2];
	char *args[N_ARGS];

	r= pipe(fds_in);	/* Input for sscclient */
	if (r == -1)
		fatal("pipe() failed: %s", strerror(errno));
	r= pipe(fds_out);	/* Output from sscclient */
	if (r == -1)
		fatal("pipe() failed: %s", strerror(errno));

	client_pid= fork();
	if (client_pid == -1)
		fatal("fork failed: %s", strerror(errno));
	if (client_pid != 0)
	{
		p_in= fds_out[0];	/* Output from sscclient */
		close(fds_out[1]);
		p_out= fds_in[1];	/* Input for sscclient */
		close(fds_in[0]);
		return;
	}

	dup2(fds_in[0], 0);		/* Input */
	close(fds_in[0]);
	close(fds_in[1]);
	dup2(fds_out[1], 1);		/* Output */
	close(fds_out[0]);
	close(fds_out[1]);

	i= 0;
	args[i++]= "sscclient";
	args[i++]= "-b";
	if (user)
	{
		args[i++]= "-l";
		args[i++]= user;
	}
	if (options)
	{
		args[i++]= "-o";
		args[i++]= options;
	}
	args[i++]= hostname;
	args[i++]= SERVICE;
	args[i++]= NULL;
	assert(i <= N_ARGS);

	/* First try the user's own version of sscclient */
	execvp("sscclient", args);

	/* Try a system version */
	execv(SSCCLIENT_PATH, args);
	fatal("execl failed: %s", strerror(errno));
}

static void read_greeting(void)
{
	int i, r;
	char line[1024];

	for (i= 0; i<sizeof(line); i++)
	{
		r= read(p_in, &line[i], 1);
		if (r <= 0)
		{
			if (r == 0 && i == 0)
				fatal("sscclient failed");
			fatal("error reading data from sscclient: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		if (line[i] == '\n')
			break;
	}
	if (i >= sizeof(line))
		fatal("too much data in read_greeting");
	if (i == 0)
		return;	/* Everything is ok */
	line[i]= '\0';
	fatal("sscclient failed: %s", line);
}

static void send_cmd_fn(u16_t cmd, char *str)
{
	size_t len, slen;
	int r;
	char *cp;
	void *buf;
	struct sscrcp_hdr *cmd_hdrp;

	slen= strlen(str);
	len= sizeof(*cmd_hdrp) + slen;
	buf= os_malloc("send_cmd_fn", len);
	cmd_hdrp= buf;
	cp= (char *)&cmd_hdrp[1];
	memcpy(cp, str, slen);

	u16_to_be(len, cmd_hdrp->srh_len);
	u16_to_be(cmd, cmd_hdrp->srh_type);
	r= writeall(buf, len);
	if (r <= 0)
	{
		fatal("unable to send command: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
}

static void send_error(char *str)
{
	ssize_t r, slen;
	u16_t len;
	char *cp;
	void *buf;
	struct sscrcp_hdr *hdrp;

	slen= strlen(str);
	len= sizeof(*hdrp) + slen;
	buf= os_malloc("send_error", len);
	hdrp= buf;
	cp= (char *)&hdrp[1];
	memcpy(cp, str, slen);

	u16_to_be(len, hdrp->srh_len);
	u16_to_be(SSCRCP_CERROR, hdrp->srh_type);

	r= writeall(buf, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));
	free(buf);
}

static void send_ok(void)
{
	ssize_t r;
	u16_t len;
	struct sscrcp_hdr hdr;

	len= sizeof(hdr);
	u16_to_be(len, hdr.srh_len);
	u16_to_be(SSCRCP_COK, hdr.srh_type);

	r= writeall(&hdr, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));
}

static char *get_status(struct sscrcp_hdr *hdrp)
{
	u16_t type, len;
	char *str;
	ssize_t r;
	struct sscrcp_hdr resp_hdr;

	if (hdrp)
	{
	}
	else
	{
		r= readall(&resp_hdr, sizeof(resp_hdr));
		if (r <= 0)
		{
			fatal("error reading reply: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		hdrp= &resp_hdr;
	}
	type= u16_from_be(hdrp->srh_type);
	len= u16_from_be(hdrp->srh_len);
	if (type == SSCRCP_SOK)
	{
		if (len != sizeof(*hdrp))
		{
			fatal("bad length %d in message type %d",
				len, type);
		}
		return NULL;
	}
	else if (type == SSCRCP_SERROR)
		;	/* Continue */
	else
		fatal("bad type in reply message: %d", type);
	if (len < sizeof(*hdrp))
		fatal("bad length in data message: %d", len);
	len -= sizeof(*hdrp);
	str= os_malloc("get_status", len+1);
	r= readall(str, len);
	if (r <= 0)
	{
		fatal("error reading reply: %s",
			r == 0 ? "unexpected EOF" : strerror(errno));
	}
	str[len]= '\0';
	pretty(str);
	return str;
}

/* Limit the contents of str to a subset of ASCII (the printable
 * characters plus space, tab, carriage return and newline.
 */
static void pretty(char *str)
{
	char *cp;
	int c;

	for (cp= str; *cp != '\0'; cp++)
	{
		c= *cp;
		if (c >= ' ' && c <= '~')
			;	/* OK */
		else if (c == '\t' || c == '\n' || c == '\r')
			;	/* OK */
		else
			*cp= '?';
	}
}

static char *dupstr(char *str)
{
	size_t len;
	char *newstr;

	len= strlen(str)+1;
	newstr= os_malloc("dupstr", len);
	strlcpy(newstr, str, len);
	assert(strlen(newstr)+1 == len);
	return newstr;
}

static char *concat3(char *str1, char *str2, char *str3)
{
	size_t len;
	char *newstr;
	
	len= strlen(str1) + strlen(str2) + strlen(str3) + 1;
	newstr= os_malloc("concat3", len);
	strlcpy(newstr, str1, len);
	strlcat(newstr, str2, len);
	strlcat(newstr, str3, len);
	assert(strlen(newstr)+1 == len);
	return newstr;
}

/* Return 1 if str contains at least one of the wildcard characters '*', '?',
 * '[', otherwise return 0.
 */
static int wildcard(char *str)
{
	/* Note: return true even if the wildcards are escaped using '\' */
	if (strchr(str, '*') || strchr(str, '?') || strchr(str, '['))
		return 1;
	return 0;
}

static int readall(void *buf, size_t size)
{
	char *p;
	size_t o;
	ssize_t r;

	p= buf;
	o= 0;
	while (o < size)
	{
		r= read(p_in, &p[o], size-o);
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

static int writeall(void *buf, size_t size)
{
	return fd_writeall(p_out, buf, size);
}

static int fd_writeall(int fd, void *buf, size_t size)
{
	char *p;
	size_t o;
	ssize_t r;

	p= buf;
	o= 0;
	while (o < size)
	{
		r= write(fd, &p[o], size-o);
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

static void u16_to_be(u16_t v, u8_t buf[2])
{
	buf[0]= ((v >> 8) & 0xff);
	buf[1]= (v & 0xff);
}

static void u32_to_be(u32_t v, u8_t buf[4])
{
	buf[0]= ((v >> 24) & 0xff);
	buf[1]= ((v >> 16) & 0xff);
	buf[2]= ((v >> 8) & 0xff);
	buf[3]= (v & 0xff);
}

static u16_t u16_from_be(u8_t buf[2])
{
	return ((u16_t)buf[0] << 8) | buf[1];
}

static u32_t u32_from_be(u8_t buf[4])
{
	return ((u32_t)buf[0] << 24) | ((u32_t)buf[1] << 16) |
		((u32_t)buf[2] << 8) | buf[3];
}

static void error(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage:\tsscrcp [-V] [-o <options>] [-p] [user@]<hostname>\n");
	fprintf(stderr,
"\tsscrsp [-o options] [-p] [user@]<hostname>:<filename> <file/dir>\n");
	fprintf(stderr,
"\tsscrsp [-o options] [-p] <file1>... [user@]<hostname>:[<file/dir>]\n");
	exit(1);
}

/*
 * $PchId: sscrcp.c,v 1.2 2005/06/01 10:17:06 philip Exp philip $
 */
