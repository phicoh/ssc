/*
os_minix.c

Operating specific functions for Minix

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/protocol.h"
#include "sscserver.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define CHILD_TO	30	/* Check this often whether the child is
				 * still alive.
				 */

char PATH_UTMP[] = "/etc/utmp";		/* current logins */
char PATH_WTMP[] = "/usr/adm/wtmp";	/* login/logout history */
char PATH_LASTLOG[] = "/usr/adm/lastlog";	/* last login history */

static pid_t child_pid;
static int parent_done= 0, child_done= 0;	
static char pty_str[]= "/dev/ptyXX";
static char tty_str[]= "/dev/ttyXX";
static char hex_str[16]= "0123456789abcdef";

/* For wtmp */
static char *hostname= NULL;

static void do_out(int p_in);
static void do_alarm(int sig);
static void do_usr2(int sig);
static void kill_parent(int sig);
static void wtmp(char *user, uid_t uid, char *id, char *line, char *hostname,
	int pid, int type, int slot);

void tcp_shutdown(int fd)
{
	syslog(LOG_ERR, "should shutdown connection\n");
}

void prepare_id(char*user)
{
	/* Nothing to do */
}

void do_inout(int p_in, int p_out)
{
	int r;
	unsigned char *buf;
	u16_t o, len, len1, extra_len, type, wo;
	struct sscp_bytes bytes_msg;

	child_pid= fork();
	if (child_pid == 0)
	{
		close(p_out);
		do_out(p_in);
	}
	if (child_pid == -1)
		fatal("fork failed: %s", strerror(errno));
	close(p_in);

	signal(SIGALRM, do_alarm);
	signal(SIGUSR2, do_usr2);
	alarm(CHILD_TO);

	/* Input from the network to the service */
	buf= os_malloc("do_inout", maxmsglen);

	for (;;)
	{
		/* Get bytes */
		r= sksc_c_readall(&bytes_msg, sizeof(bytes_msg));
		if (r == 0)
			break;
		if (r < 0)
		{
			fatal("error reading bytes from client: %s",
				strerror(errno));
		}
		len= u16_from_be(bytes_msg.sb_len);
		type= u16_from_be(bytes_msg.sb_type);

		if (type != S_BYTES_TYPE)
			shutdown_fatal("bad type in bytes message: %u", type);
		if (len < sizeof(bytes_msg)+2)
		{
			shutdown_fatal("bad length in bytes message: %u",
				len);
		}

		extra_len= len-sizeof(bytes_msg);
		if (extra_len > maxmsglen)
			fatal("bytes message too large: %u", len);
		r= sksc_c_readall(buf, extra_len);
		if (r <= 0)
		{
			fatal("error reading bytes from client: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}

		o= 0;

		/* data */
		assert(o+2 <= extra_len);
		len1= u16_from_be(buf+o);
		o += 2;
		if (o+len1 > extra_len)
		{
			shutdown_fatal(
		"error decoding client's data message (too short)");
		}

		for (wo= 0; wo<len1; wo += r)
		{
			r= write(p_out, buf+o+wo, len1-wo);
			if (r <= 0)
			{
				fatal("error writing to stdout: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
		}
		assert(wo == len1);
	}
	close(p_out);
	parent_done= 1;
	for(;;)
	{
		if (child_done)
			break;
		pause();
	}
}

void do_hostname(int fd)
{
	int r;
	size_t len;
	char *h;
	struct sockaddr_in sin;
	socklen_t size;

	size= sizeof(sin);
	r= getsockname(fd, (struct sockaddr *)&sin, &size);
	if (r == -1)
		h= "";
	else
		h= inet_ntoa(sin.sin_addr);
	len= strlen(h)+1;
	hostname= os_malloc("do_hostname", len);
	strlcpy(hostname, h, len);
	assert(strlen(hostname) == len-1);
}

void get_pty(uid_t uid, gid_t gid, int *fdp, char **tty_namep)
{
	int pty_fd;
	int i, j, r;
	struct stat sb;

	pty_fd= -1;
	j= 0;	/* lint */
	for (i= 'p'; i <= 'z'; i++)
	{
		pty_str[sizeof(pty_str)-3]= i;
		pty_str[sizeof(pty_str)-2]= '0';
		r= stat(pty_str, &sb);
		if (r == -1)
			continue;
		for (j= 0; j < 16; j++)
		{
			pty_str[sizeof(pty_str)-2]= hex_str[j];
			pty_fd= open(pty_str, O_RDWR);
			if (pty_fd != -1)
				break;
		}
		if (pty_fd != -1)
			break;
	}
	if (pty_fd == -1)
		fatal("out of ptys");

	tty_str[sizeof(pty_str)-3]= i;
	tty_str[sizeof(pty_str)-2]= hex_str[j];

  	chown(tty_str, uid, gid);
  	chmod(tty_str, 0600);

	*fdp= pty_fd;
	*tty_namep= tty_str;
}

void login_pty(char *user, uid_t uid)
{
	pid_t pid;
	int fd, type, tty_slot;

	assert(0);
#if 0
	fd= open(tty_str, O_RDWR);
	if (fd == -1)
		fatal("unable to open '%s': %s", tty_str, strerror(errno));

	pid= getpid();
	type= USER_PROCESS;
	tty_slot= fttyslot(fd);

	wtmp(user, uid, "", tty_str, hostname, pid, type, tty_slot);
#endif
}

void logout_pty()
{
	pid_t pid;
	uid_t uid;
	int fd, type, tty_slot;
	char *user;

	assert(0);
#if 0
	fd= open(tty_str, O_RDWR);
	if (fd == -1)
		fatal("unable to open '%s': %s", tty_str, strerror(errno));

	do_hostname(0);

	user= get_user();
	uid= get_pwd_entry()->pw_uid;
	pid= getpid();
	type= DEAD_PROCESS;
	tty_slot= fttyslot(fd);

	wtmp("", uid, "", tty_str, hostname, pid, type, tty_slot);

	close(fd);

	chown(tty_str, 0, 0);
	chmod(tty_str, 0666);
#endif
}

int pw_valid(struct passwd *pe, char *password)
{
	assert(0);
#if 0
	if (strcmp(crypt(password, pe->pw_passwd), pe->pw_passwd) == 0)
		return 1;
#endif
	return 0;
}

static void do_out(int p_in)
{
	int r;
	unsigned char *buf, *cp;
	u16_t o, len1, totlen, pad;
	struct sscp_bytes *bytes_msg;

	/* Output from the service to the network */
	buf= os_malloc("do_out", maxmsglen);
	bytes_msg= (struct sscp_bytes *)buf;
	for (;;)
	{
		o= sizeof(*bytes_msg)+2;
		r= read(p_in, buf+o, maxmsglen-o);
		if (r < 0)
		{
			fatal("error reading from service: %s",
				strerror(errno));
		}

		len1= r;
		assert(len1 == r);

		if (len1 == 0)
		{
			r= sksc_s_writeall(buf, 0);
			if (r <= 0)
			{
				kill_parent(SIGUSR1);
				fatal("error sending data to client: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			break;
		}

		totlen= sizeof(*bytes_msg) + 2+len1;
		if (totlen < 32)
		{
			pad= 32-totlen;
			memset(buf+totlen, '\0', pad);
		}
		else
			pad= 0;
		totlen += pad;
		u16_to_be(totlen, bytes_msg->sb_len);
		u16_to_be(S_BYTES_TYPE, bytes_msg->sb_type);

		cp= (unsigned char *)&bytes_msg[1];
		u16_to_be(len1, cp);
		cp += 2;
		cp += len1;

		if (pad)
			memset(cp, '\0', pad);
		cp += pad;

		assert(cp == buf+totlen);

		r= sksc_s_writeall(buf, totlen);
		if (r <= 0)
		{
			kill_parent(SIGUSR1);
			fatal("error sending data to client: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
		}
	}
	kill_parent(SIGUSR2);
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

static void do_usr2(int sig)
{
	child_done= 1;
	if (parent_done)
	{
		/* Set an alarm to handle race conditions */
		signal(SIGALRM, do_usr2);
		alarm(1);
	}
}

static void kill_parent(int sig)
{
	pid_t ppid;

	ppid= getppid();
	if (ppid != 1)
		kill(ppid, sig);	/* Ignore errors */
}

static void wtmp(char *user, uid_t uid, char *id, char *line,
	char *hostname, int pid, int type, int slot)
{
	/* Log an event into the UTMP and WTMP files. */

#ifdef USE_UTMP
	struct utmp utmp;		/* UTMP/WTMP User Accounting */
#else
	struct utmpx utmp;		/* UTMP/WTMP User Accounting */
#endif
	int fd= -1;
	int log = 1;			/* log in wtmp */
	char *p;

	/* Strip the /dev part of the TTY name. */
	p = strrchr(line, '/');
	if (p != 0)
	line= p+1;

#ifdef USE_UTMP
	assert(0);
	abort();
#else
	if (type == DEAD_PROCESS)
	{
		/* Don't add a logout entry for just a dying login. */
		fd= open(PATH_UTMP, O_RDONLY);
		if (fd == -1)
		{
			syslog(LOG_ERR, "unable to open '%s': %s",
				PATH_UTMP, strerror(errno));
			return;
		}
		if (lseek(fd, (off_t) slot * sizeof(utmp), SEEK_SET) != -1 &&
			read(fd, (void *) &utmp, sizeof(utmp)) == sizeof(utmp))
		{
			if (utmp.ut_type != INIT_PROCESS
				&& utmp.ut_type != USER_PROCESS)
			log= 0;
		}
		close(fd);
	}
	if (type == LOGIN_PROCESS) log= 0;	/* and don't log this one */
#endif /* USE_UTMP */

	/* Clear the utmp record. */
	memset((void *) &utmp, 0, sizeof(utmp));

#ifdef USE_UTMP
	assert(0);
	abort();
#else
	/* Enter new values. */
	strncpy(utmp.ut_user, user, sizeof(utmp.ut_user));
	strncpy(utmp.ut_id, id, sizeof(utmp.ut_id));
	strncpy(utmp.ut_line, line, sizeof(utmp.ut_line));
#ifndef ARCH_SOLARIS
	strncpy(utmp.ut_host, hostname, sizeof(utmp.ut_host));
#endif
	utmp.ut_pid = pid;
	utmp.ut_type = type;
	gettimeofday(&utmp.ut_tv, NULL);
#endif /* USE_UTMP */

	if (log) {
		fd= open(PATH_WTMP, O_WRONLY | O_APPEND);
		if (fd == -1)
		{
			syslog(LOG_ERR, "unable to open '%s': %s",
				PATH_WTMP, strerror(errno));
			return;
		}
		write(fd, (char *) &utmp, sizeof(utmp));
		close(fd);
	}

	/* write entry to utmp */
	fd= open(PATH_UTMP, O_WRONLY);
	if (fd == -1)
	{
		syslog(LOG_ERR, "unable to open '%s': %s",
			PATH_UTMP, strerror(errno));
		return;
	}
	if (lseek(fd, (off_t) slot * sizeof(utmp), SEEK_SET) != -1)
		write(fd, (char *) &utmp, sizeof(utmp));
	close(fd);

	/* Write the LASTLOG entry. */
	fd= open(PATH_LASTLOG, O_WRONLY);
	if (fd == -1)
	{
		syslog(LOG_ERR, "unable to open '%s': %s",
			PATH_LASTLOG, strerror(errno));
		return;
	}
	if (lseek(fd, (off_t) uid * sizeof(utmp), SEEK_SET) < 0)
		return;
	if (write(fd, (char *) &utmp, sizeof(utmp)) < 0)
		return;
	close(fd);
}

/*
 * $PchId: os_posix.c,v 1.2 2012/01/27 15:59:38 philip Exp $
 */
