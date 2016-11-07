/*
sscrsh.c

Execute a remote command using a secure channel

Created:	March 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/prot_rsh.h"
#include "../include/sscversion.h"

#define SSCCLIENT_PATH	"/usr/local/sbin/sscclient"

#define SERVICE "rsh"
#define CHILD_TO	30	/* Check this often whether the child is still
				 * alive
				 */

#define N_ARGS		9

static char *progname;
static int p_in, p_out;
static pid_t client_pid;
static pid_t child_pid;
static int eof_from_user= 0;
static int eof_from_net= 0;

static void start_client(char *hostname, char *user, char *options);
static void read_greeting(void);
static void send_command(int argc, char *argv[]);
static void do_inout(void);
static void do_out(void);
static void do_alarm(int sig);
static void do_usr1(int sig);
static void do_usr2(int sig);
static int readall(void *buf, size_t size);
static int writeall(void *buf, size_t size);
static void u16_to_be(u16_t v, u8_t buf[2]);
static void u32_to_be(u32_t v, u8_t buf[4]);
static u16_t u16_from_be(u8_t buf[2]);
static u32_t u32_from_be(u8_t buf[4]);
static void fatal(char *fmt, ...);
static void fatal_kill(char *fmt, ...);
static void usage(void);

int main(int argc, char *argv[])
{
	int c;
	char *p, *hostname, *options, *user;
	int n_flag;
	char *l_arg, *o_arg;

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	n_flag= 0;
	l_arg= NULL;
	o_arg= NULL;
	while (c=getopt(argc, argv, "l:no:V?"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'l':
			l_arg= optarg;
			break;
		case 'n':
			n_flag= 1;
			break;
		case 'o':
			o_arg= optarg;
			break;
		case 'V':
			fatal("version %s", sscversion);
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	if (optind >= argc)
		usage();
	hostname= argv[optind++];

	if (optind == argc)
	{
		/* We want remote login. Exec ssctelnet */
		execvp("ssctelnet", argv);
		fatal("execvp of ssctelnet failed: %s", strerror(errno));
	}

	if (optind > argc)	/* Can this actually happen? */
		usage();

	user= l_arg;
	options= o_arg;

	/* Parse user@host */
	p= strchr(hostname, '@');
	if (p)
	{
		*p= '\0';
		user= hostname;
		hostname= p+1;
	}

	start_client(hostname, user, options);
	read_greeting();
	send_command(argc-optind, &argv[optind]);
	if (n_flag)
		do_out();
	else
		do_inout();
	exit(1);	/* lint */
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

static void send_command(int argc, char *argv[])
{
	size_t len, cmdlen;
	int i, r;
	char *str;
	void *buf;
	struct sscrsh_cmd *cmd_hdrp;

	/* Compute length of string */
	cmdlen= 0;
	for (i= 0; i<argc; i++)
		cmdlen += strlen(argv[i])+1;

	len= sizeof(*cmd_hdrp) + cmdlen;
	buf= os_malloc("send_command", len);
	cmd_hdrp= buf;
	str= (char *)&cmd_hdrp[1];
	strlcpy(str, argv[0], cmdlen);
	for (i= 1; i<argc; i++)
	{
		strlcat(str, " ", cmdlen);
		strlcat(str, argv[i], cmdlen);
	}
	assert(strlen(str)+1 == cmdlen);

	u16_to_be(len, cmd_hdrp->src_len);
	u16_to_be(RSH_CMD_TYPE, cmd_hdrp->src_type);
	r= writeall(buf, len);
	if (r <= 0)
	{
		fatal("unable to send command: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
}

static void do_inout(void)
{
	ssize_t r, buflen;
	u16_t len;
	char *cp;
	void *buf;
	struct sscrsh_data *data_hdrp;

	signal(SIGUSR1, do_usr1);
	signal(SIGUSR2, do_usr2);
	child_pid= fork();
	if (child_pid == -1)
		fatal("fork failed: %s", strerror(errno));
	if (child_pid == 0)
	{
		close(p_out);
		do_out();
	}

	buflen= 16*1024;
	buf= os_malloc("do_inout", buflen);
	data_hdrp= buf;
	cp= (char *)&data_hdrp[1];

	signal(SIGALRM, do_alarm);
	alarm(CHILD_TO);
	for(;;)
	{
		len= buflen-sizeof(*data_hdrp);
		assert(len > 0);
		r= read(0, cp, len);
		if (r == 0)
			break;
		if (r == -1)
		{
			if (errno == EINTR)
			{
				if (eof_from_net)
				{
					/* We are done. The remote shell
					 * command closed stdout/stderr.
					 * (probably by exiting).
					 */
					break;
				}
				continue;
			}
			fatal("error reading from stdin: %s", strerror(errno));
		}

		len= sizeof(*data_hdrp)+r;
		u16_to_be(len, data_hdrp->srd_len);
		u16_to_be(RSH_STDIN_TYPE, data_hdrp->srd_type);

		writeall(buf, len);
	}

	/* Send EOF message */
	len= sizeof(*data_hdrp);
	u16_to_be(len, data_hdrp->srd_len);
	u16_to_be(RSH_STDIN_TYPE, data_hdrp->srd_type);
	writeall(buf, len);

	eof_from_user= 1;
	close(p_out);
	for(;;)
	{
		if (eof_from_net)
			break;
		pause();
	}

	/* Done */
	exit(0);
}

static void do_out(void)
{
	pid_t ppid;
	size_t o, o1, n, n1, buflen;
	ssize_t r;
	int fd, eof_stdout, eof_stderr;
	u16_t len, type;
	void *buf;
	char *cp;
	struct sscrsh_data data_hdr;


	buflen= 2*PIPE_BUF;
	buf= os_malloc("do_out", buflen);

	eof_stdout= 0;
	eof_stderr= 0;
	fd= -1;	/* lint */
	for (;;)
	{
		r= readall(&data_hdr, sizeof(data_hdr));
		if (r == 0)
			break;
		if (r < 0)
		{
			fatal("error reading data message: %s",
				strerror(errno));
		}
		type= u16_from_be(data_hdr.srd_type);
		if (type == RSH_STDOUT_TYPE)
			fd= 1;
		else if (type == RSH_STDERR_TYPE)
			fd= 2;
		else
			fatal("bad type in data message: %d", type);
		len= u16_from_be(data_hdr.srd_len);
		if (len < sizeof(data_hdr))
			fatal("bad length in data message: %d", len);
		len -= sizeof(data_hdr);
		if (len == 0)
		{
			if (fd == 1)
				eof_stdout= 1;
			else
				eof_stderr= 1;
			close(fd);
			if (eof_stdout && eof_stderr)
				break;
		}
		for (o= 0; o<len; o += n)
		{
			n= len-o;
			if (n > buflen)
				n= buflen;
			r= readall(buf, n);
			if (r <= 0)
			{
				fatal("error reading data message: %s",
					r == 0 ? "EOF" : strerror(errno));
			}
			for (cp= buf, o1= 0; o1 < n; cp += r, o1 += r)
			{
				n1= n-o1;
				r= write(fd, cp, n1);
				if (r <= 0)
				{
					fatal("error writing to fd %d: %s",
						fd, r == 0 ? "EOF" :
						strerror(errno));
				}
			}
		}
	}

	if (eof_stdout && eof_stderr)
	{
		ppid= getppid();
		if (ppid != 1)
			kill(ppid, SIGUSR2);
	}
	else
		fatal_kill("lost input from client");
	exit(0);
}

static void do_alarm(int sig)
{
	pid_t pid;
	int sb;

	signal(SIGALRM, do_alarm);

	pid= waitpid(child_pid, &sb, WNOHANG);
	if (pid == child_pid)
		fatal("child died");

	alarm(CHILD_TO);
}

static void do_usr1(int sig)
{
	/* Child lost input */
	exit(1);
}

static void do_usr2(int sig)
{
	/* Child is done. Did we get EOF before? */
	if (eof_from_user)
		exit(0);

	eof_from_net= 1;
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
	char *p;
	size_t o;
	ssize_t r;

	p= buf;
	o= 0;
	while (o < size)
	{
		r= write(p_out, &p[o], size-o);
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

static void fatal_kill(char *fmt, ...)
{
	va_list ap;
	pid_t ppid;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	ppid= getppid();
	if (ppid != 1)
		kill(ppid, SIGUSR1);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: sscrsh [-nV] [-l <rem-user>] [-o <options>]\n"
		"\t\t[<rem-user>@]<hostname> [<command> [<string>]...]\n");
	exit(1);
}

/*
 * $PchId: sscrsh.c,v 1.2 2005/06/01 10:14:19 philip Exp philip $
 */
