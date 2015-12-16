/*
sscrshd.c

Server for remote command execution

Created:	March 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/prot_rsh.h"

#define SHELL "/bin/sh"
#if 0 /* For Android: (should be moved to os.h) */
#undef SHELL
#define SHELL "/system/bin/sh"
#endif

#define RETRY_FAST_NR	10
#define SHORT_TO	 1
#define LONG_TO		10

static char *progname;
static char *cmd;
static int fd_to_in, fd_from_out, fd_from_err;
static pid_t child_pid;
static int eof_from_net= 0;
static int eof_from_shell= 0;

static void read_command(void);
static void ch_pgrp(void);
static void exec_cmd(char *cmd);
static void do_pipe(int fds[2]);
static void do_in(void);
static void do_outerr(void);
static void do_out(void *buf, size_t bufsize);
static ssize_t do_out1(void *buf, size_t bufsize);
static void do_err(void *buf, size_t bufsize);
static ssize_t do_err1(void *buf, size_t bufsize);
static void do_alarm(int sig);
static void do_usr2(int sig);
static int readall(void *buf, size_t size);
static ssize_t writeall(void *buf, size_t size);
static void u16_to_be(U16_t v, u8_t buf[2]);
static void u32_to_be(u32_t v, u8_t buf[4]);
static u16_t u16_from_be(u8_t buf[2]);
static u32_t u32_from_be(u8_t buf[4]);
static void fatal(char *fmt, ...);
static void fatal_kill(char *fmt, ...);

int main(int argc, char *argv[])
{
	int fd;
	char *home;

	openlog("sscrshd", LOG_CONS, LOG_AUTH);

	(progname=strrchr(argv[0], '/')) ? progname++ : (progname=argv[0]);

	/* Change to the user's home directory. Ignore errors. */
	home= getenv("HOME");
	if (home)
		(void)chdir(home);

	read_command();

	ch_pgrp();

	exec_cmd(cmd);

	signal(SIGUSR2, do_usr2);

	child_pid= fork();
	if (child_pid == -1)
		fatal("fork failed: %s", strerror(errno));
	if (child_pid == 0)
	{
		/* Release stdout and stderr, make sure that a close of stdout
		 * gets detected.
		 */
		fd= open("/dev/null", O_WRONLY);
		if (fd == -1)
			fatal("unable to open /dev/null: %s", strerror(errno));
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);

		do_in();
	}

	/* Close fd_to_in to make sure that when the child is done, EOF
	 * propages to the shell command.
	 */
	close(fd_to_in);

	do_outerr();

	exit(1);	/* lint */
}

static void read_command(void)
{
	int r;
	u16_t len, type;
	struct sscrsh_cmd cmd_hdr;

	r= readall(&cmd_hdr, sizeof(cmd_hdr));
	if (r <= 0)
	{
		fatal("unable to read command: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
	len= u16_from_be(cmd_hdr.src_len);
	type= u16_from_be(cmd_hdr.src_type);

	if (type != RSH_CMD_TYPE)
		fatal("bad type in command message: %d", type);

	if (len <= sizeof(cmd_hdr))
		fatal("bad length in command message: %d", len);

	len -= sizeof(cmd_hdr);
	cmd= os_malloc("read_command", len+1);
	r= readall(cmd, len);
	if (r <= 0)
	{
		fatal("unable to read command: %s",
			r == 0 ? "EOF" : strerror(errno));
	}
	cmd[len]= '\0';
}

static void ch_pgrp(void)
{
	pid_t pgrp;

	/* Starting a new session is the most portable way to create a
	 * new process group in POSIX systems.
	 */
	pgrp= setsid();
	if (pgrp == -1)
		fatal("setsid() failed: %s", strerror(errno));
}

static void exec_cmd(char *cmd)
{
	int fds_in[2], fds_out[2], fds_err[2];
	pid_t pid;

	do_pipe(fds_in);
	do_pipe(fds_out);
	do_pipe(fds_err);

	pid= fork();
	if (pid == -1)
		fatal("fork failed: %s", strerror(errno));
	if (pid != 0)
	{
		/* Handle pipes */
		fd_to_in= fds_in[1];
		close(fds_in[0]);
		fd_from_out= fds_out[0];
		close(fds_out[1]);
		fd_from_err= fds_err[0];
		close(fds_err[1]);
		return;
	}

	/* Setup stdin, stdout, stderr */
	dup2(fds_in[0], 0);
	close(fds_in[0]);
	close(fds_in[1]);
	dup2(fds_out[1], 1);
	close(fds_out[0]);
	close(fds_out[1]);
	dup2(fds_err[1], 2);
	close(fds_err[0]);
	close(fds_err[1]);

	execl(SHELL, SHELL, "-c", cmd, NULL);
	fatal("execl of %s failed: %s", SHELL, strerror(errno));
}

static void do_pipe(int fds[2])
{
	int r;

	r= pipe(fds);
	if (r == -1)
		fatal("pipe() failed: %s", strerror(errno));
}

static void do_in(void)
{
	size_t o, o1, n, n1, buflen;
	ssize_t r;
	u16_t len, type;
	pid_t ppid;
	void *buf;
	char *cp;
	struct sscrsh_data data_hdr;


	buflen= 2*PIPE_BUF;
	buf= os_malloc("do_in", buflen);

	for (;;)
	{
		r= readall(&data_hdr, sizeof(data_hdr));
		if (r <= 0)
		{
			fatal_kill("error reading data message: %s",
				r == 0 ? "EOF" : strerror(errno));
		}
		type= u16_from_be(data_hdr.srd_type);
		if (type != RSH_STDIN_TYPE)
			fatal("bad type in data message: %d", type);
		len= u16_from_be(data_hdr.srd_len);
		if (len < sizeof(data_hdr))
			fatal("bad length in data message: %d", len);
		len -= sizeof(data_hdr);
		if (len == 0)
			break;	/* EOF */
		for (o= 0; o<len; o += n)
		{
			n= len-o;
			if (n > buflen)
				n= buflen;
			r= readall(buf, n);
			if (r <= 0)
			{
				fatal_kill("error reading data message: %s",
					r == 0 ? "EOF" : strerror(errno));
				break;
			}
			for (cp= buf, o1= 0; o1 < n; cp += r, o1 += r)
			{
				n1= n-o1;
				r= write(fd_to_in, cp, n1);
				if (r <= 0)
				{
					fatal("error writing to fd %d: %s",
						fd_to_in, r == 0 ? "EOF" :
						strerror(errno));
				}
			}
		}
	}

	/* Signal parent */
	ppid= getppid();
	if (ppid != 1)
		kill(ppid, SIGUSR2);

	/* Done */
	exit(0);
}

static void do_outerr(void)
{
	size_t buflen;
	void *buf;
	int r, retries;

	/* Use alarm to multiplex reading stdout and stderr data */

	buflen= 16*1024;
	buf= os_malloc("do_outerr", buflen);

	signal(SIGALRM, do_alarm);
	retries= 0;
	for(;;)
	{
		if (retries < RETRY_FAST_NR)
			alarm(SHORT_TO);
		else
			alarm(LONG_TO);
		r= do_out1(buf, buflen);
		if (r > 0)
		{
			retries= 0;
			continue;
		}
		if (r == 0)
			do_err(buf, buflen);

		for(;;)
		{
			alarm(SHORT_TO);
			r= do_err1(buf, buflen);
			if (r > 0)
			{
				retries= 0;
				continue;
			}
			if (r == 0)
				do_out(buf, buflen);
			break;
		}
		retries++;
	}
}

static void do_out(void *buf, size_t bufsize)
{
	int r;

	for(;;)
	{
		alarm(30);
		r= do_out1(buf, bufsize);
		if (r == 0)
			break;
		assert(r > 0);
	}

	eof_from_shell= 1;
	for(;;)
	{
		if (eof_from_net)
		{
			/* Kill shell */
			kill(0, SIGHUP);

			/* Just in case we didn't die */
			exit(0);
		}
		pause();
	}
}

static ssize_t do_out1(void *buf, size_t bufsize)
{
	ssize_t r;
	u16_t len;
	char *cp;
	struct sscrsh_data *data_hdrp;

	data_hdrp= buf;
	cp= (char *)&data_hdrp[1];
	len= bufsize-sizeof(*data_hdrp);
	assert(len > 0);
	r= read(fd_from_out, cp, len);
	if (r == 0)
	{
		/* Send EOF */
		len= sizeof(*data_hdrp);
		u16_to_be(len, data_hdrp->srd_len);
		u16_to_be(RSH_STDOUT_TYPE, data_hdrp->srd_type);
		writeall(buf, len);

		return 0;
	}
	if (r == -1)
	{
		if (errno == EINTR)
			return -1;
		fatal("error reading stdout from shell: %s", strerror(errno));
	}

	len= sizeof(*data_hdrp)+r;
	u16_to_be(len, data_hdrp->srd_len);
	u16_to_be(RSH_STDOUT_TYPE, data_hdrp->srd_type);

	writeall(buf, len);
	return r;
}

static void do_err(void *buf, size_t bufsize)
{
	int r;

	for(;;)
	{
		alarm(30);
		r= do_err1(buf, bufsize);
		if (r == 0)
			break;
		assert(r > 0);
	}

	eof_from_shell= 1;
	for(;;)
	{
		if (eof_from_net)
		{
			/* Kill shell */
			kill(0, SIGHUP);

			/* Just in case we didn't die */
			exit(0);
		}
		pause();
	}
}

static ssize_t do_err1(void *buf, size_t bufsize)
{
	ssize_t r;
	u16_t len;
	char *cp;
	struct sscrsh_data *data_hdrp;

	data_hdrp= buf;
	cp= (char *)&data_hdrp[1];
	len= bufsize-sizeof(*data_hdrp);
	assert(len > 0);
	r= read(fd_from_err, cp, len);
	if (r == 0)
	{
		/* Send EOF */
		len= sizeof(*data_hdrp);
		u16_to_be(len, data_hdrp->srd_len);
		u16_to_be(RSH_STDERR_TYPE, data_hdrp->srd_type);
		writeall(buf, len);

		return 0;
	}
	if (r == -1)
	{
		if (errno == EINTR)
			return -1;
		fatal("error reading stderr from shell: %s", strerror(errno));
	}

	len= sizeof(*data_hdrp)+r;
	u16_to_be(len, data_hdrp->srd_len);
	u16_to_be(RSH_STDERR_TYPE, data_hdrp->srd_type);

	writeall(buf, len);
	return r;
}


static void do_alarm(int sig)
{
	pid_t pid;
	int sb;

	signal(SIGALRM, do_alarm);
	alarm(1);

	/* Check whether child is still alive */
	pid= waitpid(child_pid, &sb, WNOHANG);
	if (pid == child_pid)
	{
		if (eof_from_net)
		{
			/* Shutdown */
			kill(0, SIGHUP);

			/* In case we didn't die */
			exit(0);
		}
		fatal_kill("child died");
	}
}

static void do_usr2(int sig)
{
	syslog(LOG_ERR, "in do_usr2");
	eof_from_net= 1;
	if (eof_from_shell)
	{
		/* Done */

		kill(0, SIGHUP);

		/* Just in case */
		exit(0);
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
	ssize_t r;
	size_t n, o;
	char *cp;

	for (cp= buf, o= 0; o < size; cp += r, o += r)
	{
		assert(o < size);
		n= size-o;
		r= write(1, cp, n);
		if (r <= 0)
			return r;
	}
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

static void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}

static void fatal_kill(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);

	/* Kill entire process group */
	kill(0, SIGHUP);

	/* In case we didn't die */
	exit(1);
}

/*
 * $PchId: sscrshd.c,v 1.2 2011/12/27 22:56:03 philip Exp $
 */
