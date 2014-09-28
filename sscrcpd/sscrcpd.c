/*
sscrcpd.c

Server for remote file transfer using a secure connection

Created:	March 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/prot_rcp.h"

/* All mode bits */
#define S_MODEMASK (S_ISUID|S_ISGID|S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

static char *progname;
struct
{
	struct sscrcp_hdr hdr;
	char buf[16*1024];
} data_msg;

static void do_command(void);
static void do_get(char *fn);
static void do_put(char *fn);
static void do_getmode(char *fn);
static void do_gettimes(char *fn);
static void do_setmode(struct sscrcp_hdr *hdrp);
static void do_settimes(struct sscrcp_hdr *hdrp);
static void do_listdir(char *fn);
static void do_quit(void);
static void cancel_sink(struct sscrcp_hdr *hdrp);
static void send_error(char *str);
static void send_ok(void);
static void send_fn(char *fn);
static char *get_status(struct sscrcp_hdr *hdrp);
static void pretty(char *str);
static int readall(void *buf, size_t size);
static int writeall(void *buf, size_t size);
static int fd_writeall(int fd, void *buf, size_t size);
static void u16_to_be(U16_t v, u8_t buf[2]);
static void u32_to_be(u32_t v, u8_t buf[4]);
static u16_t u16_from_be(u8_t buf[2]);
static u32_t u32_from_be(u8_t buf[4]);
static void error(char *fmt, ...);
static void fatal(char *fmt, ...);

int main(int argc, char *argv[])
{
	char *home;

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	/* Change to the user's home directory. Ignore errors. */
	home= getenv("HOME");
	if (home)
		(void)chdir(home);

	for(;;)
	{
		do_command();
	}
}

static void do_command(void)
{
	int r;
	char *fn;
	u16_t len, type;
	struct sscrcp_hdr cmd_hdr;

	r= readall(&cmd_hdr, sizeof(cmd_hdr));
	if (r <= 0)
	{
		fatal("unable to read command: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
	len= u16_from_be(cmd_hdr.srh_len);
	type= u16_from_be(cmd_hdr.srh_type);

	/* Get filename argument */
	fn= NULL;
	switch(type)
	{
	case SSCRCP_GET:
	case SSCRCP_PUT:
	case SSCRCP_GETMODE:
	case SSCRCP_GETTIMES:
	case SSCRCP_LISTDIR:
		if (len < sizeof(cmd_hdr))
			fatal("bad length %d for type %d", len, type);
		len -= sizeof(cmd_hdr);
		fn= os_malloc("do_command", len+1);
		r= readall(fn, len);
		if (r <= 0)
		{
			fatal("error reading filename: %s",
				r == 0 ? "EOF" : strerror(errno));
		}
		fn[len]= '\0';
		break;
	}

	switch(type)
	{
	case SSCRCP_GET:
		do_get(fn);
		break;
	case SSCRCP_PUT:
		do_put(fn);
		break;
	case SSCRCP_GETMODE:
		do_getmode(fn);
		break;
	case SSCRCP_GETTIMES:
		do_gettimes(fn);
		break;
	case SSCRCP_SETMODE:
		do_setmode(&cmd_hdr);
		break;
	case SSCRCP_SETTIMES:
		do_settimes(&cmd_hdr);
		break;
	case SSCRCP_LISTDIR:
		do_listdir(fn);
		break;
	case SSCRCP_QUIT:
		do_quit();
		break;
	case SSCRCP_CCANCEL:
		break;		/* Ignore cancel */
	default:
		fatal("unknown message type 0x%x", type);
	}
	if (fn) free(fn);
}

static void do_get(char *fn)
{
	int fd;
	u16_t len;
	ssize_t r;

	fd= open(fn, O_RDONLY);
	if (fd == -1)
	{
		send_error(strerror(errno));
		return;
	}
	else
		send_ok();

	/* Copy loop */
	for (;;)
	{
		r= read(fd, data_msg.buf, sizeof(data_msg.buf));
		if (r <= 0)
			break;
		len= sizeof(data_msg.hdr)+r;
		u16_to_be(len, data_msg.hdr.srh_len);
		u16_to_be(SSCRCP_SDATA, data_msg.hdr.srh_type);
		r= writeall(&data_msg, len);
		if (r <= 0)
		{
			fatal("write failed: %s",
				r == 0 ? "EOF" : strerror(errno));
		}
	}
	if (r == 0)
		send_ok();
	else
		send_error(strerror(errno));
	close(fd);
}

static void do_put(char *fn)
{
	int fd, failed, t_errno;
	u16_t len, type;
	char *str;
	ssize_t r;
	size_t n, o;
	struct sscrcp_hdr hdr;
	struct utimbuf ub;

	fd= open(fn, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd == -1)
	{
		send_error(strerror(errno));
		return;
	}
	else
		send_ok();

	/* Copy loop */
	failed= 0;
	t_errno= 0;	/* LINT */
	for(;;)
	{
		r= readall(&hdr, sizeof(hdr));
		if (r <= 0)
		{
			fatal("error reading message: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
		}
		type= u16_from_be(hdr.srh_type);
		len= u16_from_be(hdr.srh_len);
		if (type != SSCRCP_CDATA)
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
				fatal("error reading data: %s",
					r == 0 ? "unexpected EOF" :
					strerror(errno));
			}

			r= fd_writeall(fd, data_msg.buf, r);
			if (r <= 0)
			{
				error("error writing to %s: %s",
					fn,
					r == 0 ? "unexpected EOF" :
					strerror(errno));
				failed= 1;
				t_errno= errno;
				break;
			}
		}
		if (failed)
			break;
	}

	if (failed)
	{
		cancel_sink(&hdr);
		type= u16_from_be(hdr.srh_type);
	}
	
	if (type == SSCRCP_COK)
		;	/* OK */
	else if (type == SSCRCP_CERROR)
	{
		str= get_status(&hdr);
		error("unable to get '%s': %s\n", fn, str);

		/* Set data to origine to indicate failed */
		ub.actime= 0;
		ub.modtime= 0;
		(void) utime(fn, &ub);
	}
	else
		fatal("bad message type %d", type);

	if (failed)
		send_error(strerror(t_errno));
	else
		send_ok();
	close(fd);
}

static void do_getmode(char *fn)
{
	int r;
	u16_t len;
	struct sscrcp_mode_repl repl;
	struct stat sb;

	r= stat(fn, &sb);
	if (r != 0)
	{
		send_error(strerror(errno));
		return;
	}

	len= sizeof(repl);
	u16_to_be(len, repl.srmr_len);
	u16_to_be(SSCRCP_MODE_REPL, repl.srmr_type);
	u16_to_be(sb.st_mode, repl.srmr_mode);
	r= writeall(&repl, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));
}

static void do_gettimes(char *fn)
{
	int r;
	u16_t len;
	struct sscrcp_times_repl repl;
	struct stat sb;

	r= stat(fn, &sb);
	if (r != 0)
	{
		send_error(strerror(errno));
		return;
	}

	len= sizeof(repl);
	u16_to_be(len, repl.srtr_len);
	u16_to_be(SSCRCP_TIMES_REPL, repl.srtr_type);
	u32_to_be(0, repl.srtr_atime_high);
	u32_to_be(sb.st_atime, repl.srtr_atime_low);
	u32_to_be(0, repl.srtr_atime_frac);
	u32_to_be(0, repl.srtr_mtime_high);
	u32_to_be(sb.st_mtime, repl.srtr_mtime_low);
	u32_to_be(0, repl.srtr_mtime_frac);
	r= writeall(&repl, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));
}

static void do_setmode(struct sscrcp_hdr *hdrp)
{
	size_t offset;
	u16_t len, mode;
	ssize_t r;
	char *cp, *fn;
	struct sscrcp_setmode setmode_hdr;
	struct stat sb;

	len= u16_from_be(hdrp->srh_len);
	if (len < sizeof(setmode_hdr))
		fatal("do_setmode: bad length %d", len);

	/* Copy initial part of header */
	memcpy(&setmode_hdr, hdrp, sizeof(*hdrp));

	/* Get remainder of header */
	offset= sizeof(*hdrp);
	cp= (char *)&setmode_hdr;
	r= readall(&cp[offset], sizeof(setmode_hdr)-offset);
	if (r <= 0)
	{
		fatal("do_setmode: error reading header: %s",
			r == 0 ? "EOF" : strerror(errno));
	}

	len -= sizeof(setmode_hdr);
	fn= os_malloc("do_setmode", len+1);
	r= readall(fn, len);
	if (r <= 0)
	{
		fatal("do_setmode: error reading filename: %s",
				r == 0 ? "EOF" : strerror(errno));
	}
	fn[len]= '\0';

	mode= u16_from_be(setmode_hdr.srsm_mode);

	/* Mask type bits */
	mode &= S_MODEMASK;

	/* Avoid changing calling chmod if it is not necessary */
	r= stat(fn, &sb);
	if (r == 0 && (sb.st_mode & S_MODEMASK) == mode)
	{
		free(fn);
		send_ok();
		return;
	}

	r= chmod(fn, mode);
	if (r == 0)
		send_ok();
	else
		send_error(strerror(errno));
	free(fn);
}

static void do_settimes(struct sscrcp_hdr *hdrp)
{
	size_t offset;
	u16_t len;
	u32_t t_a_hi, t_a, t_m_hi, t_m;
	ssize_t r;
	char *cp, *fn;
	struct sscrcp_settimes settimes_hdr;
	struct utimbuf ub;

	len= u16_from_be(hdrp->srh_len);
	if (len < sizeof(settimes_hdr))
		fatal("do_settimes: bad length %d", len);

	/* Copy initial part of header */
	memcpy(&settimes_hdr, hdrp, sizeof(*hdrp));

	/* Get remainder of header */
	offset= sizeof(*hdrp);
	cp= (char *)&settimes_hdr;
	r= readall(&cp[offset], sizeof(settimes_hdr)-offset);
	if (r <= 0)
	{
		fatal("do_settimes: error reading header: %s",
			r == 0 ? "EOF" : strerror(errno));
	}

	len -= sizeof(settimes_hdr);
	fn= os_malloc("do_settimes", len+1);
	r= readall(fn, len);
	if (r <= 0)
	{
		fatal("do_settimes: error reading filename: %s",
				r == 0 ? "EOF" : strerror(errno));
	}
	fn[len]= '\0';

	t_a_hi= u32_from_be(settimes_hdr.srst_atime_high);
	t_a= u32_from_be(settimes_hdr.srst_atime_low);
	t_m_hi= u32_from_be(settimes_hdr.srst_mtime_high);
	t_m= u32_from_be(settimes_hdr.srst_mtime_low);
	/* Ignore fractions */

	if (t_a_hi != 0 || t_m_hi)
	{
		free(fn);
		send_error("timestamp out of range");
		return;
	}

	ub.actime= t_a;
	ub.modtime= t_m;
	r= utime(fn, &ub);
	if (r == 0)
		send_ok();
	else
		send_error(strerror(errno));
	free(fn);
}

static void do_listdir(char *fn)
{
	DIR *dir;
	struct dirent *de;

	dir= opendir(fn);
	if (dir == NULL)
	{
		send_error(strerror(errno));
		return;
	}
	while(errno= 0, de= readdir(dir), de != NULL)
	{
		if (strcmp(de->d_name, ".") == 0 ||
			strcmp(de->d_name, "..") == 0)
		{
			/* Skip '.' and '..' */
			continue;
		}
		send_fn(de->d_name);
	}
	if (errno == 0)
		send_ok();
	else
		send_error(strerror(errno));
	closedir(dir);
}

static void do_quit(void)
{
	send_ok();
	exit(0);
}

static void cancel_sink(struct sscrcp_hdr *hdrp)
{
	u16_t len, type;
	size_t n, o;
	int r;
	struct sscrcp_hdr hdr;

	len= sizeof(hdr);
	u16_to_be(len, hdr.srh_len);
	u16_to_be(SSCRCP_SCANCEL, hdr.srh_type);

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
		if (type != SSCRCP_CDATA)
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
	u16_to_be(SSCRCP_SERROR, hdrp->srh_type);

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
	u16_to_be(SSCRCP_SOK, hdr.srh_type);

	r= writeall(&hdr, len);
	if (r <= 0)
		fatal("write failed: %s", r == 0 ? "EOF" : strerror(errno));
}

static void send_fn(char *str)
{
	size_t len, slen;
	int r;
	char *cp;
	void *buf;
	struct sscrcp_hdr *hdrp;

	slen= strlen(str);
	len= sizeof(*hdrp) + slen;
	buf= os_malloc("send_fn", len);
	hdrp= buf;
	cp= (char *)&hdrp[1];
	memcpy(cp, str, slen);

	u16_to_be(len, hdrp->srh_len);
	u16_to_be(SSCRCP_DIRENTRY, hdrp->srh_type);
	r= writeall(buf, len);
	if (r <= 0)
	{
		fatal("unable to send reply: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
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
	if (type == SSCRCP_COK)
	{
		if (len != sizeof(*hdrp))
		{
			fatal("bad length %d in message type %d",
				len, type);
		}
		return NULL;
	}
	else if (type == SSCRCP_CERROR)
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

static int readall(void *buf, size_t size)
{
	ssize_t r;
	size_t n, o;
	char *cp;

	for (cp= buf, o= 0; o < size; cp += r, o += r)
	{
		assert(o < size);
		n= size-o;
		r= read(0, cp, n);
		if (r <= 0)
			return r;
	}
	return size;
}

static ssize_t writeall(void *buf, size_t size)
{
	return fd_writeall(1, buf, size);
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

static void u16_to_be(U16_t v, u8_t buf[2])
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
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}

/*
 * $PchId: sscrcpd.c,v 1.1 2005/05/13 13:10:47 philip Exp $
 */
