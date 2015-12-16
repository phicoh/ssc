/*
ssctelnetd.c (from in.telnetd.c)

Server for the telnet protocol over a secure connection

Created:	May 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"

#include <ctype.h>
#include <termios.h>
#include <time.h>
#include <utmp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "../include/telnet.h"

#define NMAX	30
#define N_ARGS	20	/* Max number of arguments for login shell */

#define PATH_MOTD	"/etc/motd"

char *prog_name;
char *hostname= "unknown";
unsigned char line[1024];
unsigned char line2[2*1024];
int initial_count= 0;
char lusername[NMAX+1], rusername[NMAX+1];
char term[5+256+1]= "TERM=network";
char display[8+256+1]= "DISPLAY=";
int pty_fd= -1;
int strict_cr;
int lonely_cr= 0;

typedef void (*of_t)(int fd, unsigned char option, int enable);
typedef void (*osf_t)(int fd, unsigned char option, unsigned char *buf, size_t size);

static void opt_null(int fd, unsigned char option, int enable);
static void opt_termtype(int fd, unsigned char option, int enable);
static void opt_termsubtype(int fd, unsigned char option, unsigned char *buf,
	size_t);
static void opt_termspeed(int fd, unsigned char option, int enable);
static void opt_termsubspeed(int fd, unsigned char option, unsigned char *buf,
	size_t);
static void opt_naws(int fd, unsigned char option, unsigned char *buf, size_t);
static void opt_xdisploc(int fd, unsigned char option, int enable);
static void opt_xdisplocsub(int fd, unsigned char option, unsigned char *buf,
	size_t);
static int start_shell(void);
static char *concatstr(char *str1, char *str2);
static void fatal(char *fmt, ...);
static void show_file(char *filename);

struct option
{
	int option;	/* Number of this option */
	char *label;	/* Name of this option */
	int state;	/* 0, 1 or 2. 0 means off. If func is null, this
			 * option can't be turned on. 1 means on, can be
			 * turned off. 2 means on and cannot be turned off.
			 * server will exit of the peer refuces this option.
			 */
	int acked;	/* Received confirmation from the peer */
	of_t func;	/* Callback function when this option is received */
};

struct option local_options[]=		/* WILL / WON'T */
{
	{ TELOPT_ECHO, "echo",
		2, 0, opt_null, },
	{ TELOPT_SUP_GO_AHEAD, "suppress-go-ahead",
		2, 0, opt_null, },
	{ -1, NULL }	/* end */
};

struct option remote_options[]=		/* DO / DON'T */
{
	{ TELOPT_SUP_GO_AHEAD, "suppress-go-ahead",
		0, 0, opt_null, },
	{ TELOPT_TERMINAL_TYPE, "terminal-type",
		1, 0, opt_termtype, },
	{ TELOPT_TERMINAL_SPEED, "terminal-speed",
		0, 0, opt_termspeed, },
	{ TELOPT_XDISPLOC, "x-display-location",
		1, 0, opt_xdisploc, },
	{ TELOPT_NAWS, "window-size",
		1, 0, opt_null, },
	{ -1, NULL }	/* end */

};

static struct suboption
{
	int option;	/* Number of this option */
	osf_t func;	/* Callback function for subnegotiation */
} suboptions[]=
{
	{ TELOPT_TERMINAL_TYPE,		opt_termsubtype },
	{ TELOPT_TERMINAL_SPEED,	opt_termsubspeed },
	{ TELOPT_NAWS,			opt_naws },
	{ TELOPT_XDISPLOC,		opt_xdisplocsub },
	{ -1 }		/* end */
};

static int got_termtype= 0;	/* 1 if we got one, -1 if we won't get one */
static int got_xdisploc= 0;	/* 1 if we got one, -1 if we won't get one */
static int remote_echo= 1;	/* what about local echo */
static unsigned term_width= 0;
static unsigned term_height= 0;
static speed_t term_ispeed= B0;
static speed_t term_ospeed= B0;

int main(int argc, char *argv[]);
static void do_options(void);
static int do_control(unsigned char *buf, size_t size);
static void process_option(int fd, unsigned char cmd, unsigned char option);
static char *cmd_name(unsigned char cmd);
static void write_cmd(int fd, unsigned char *buf, size_t size);
static int options_done(void);
static void do_child(int tty_fd, char *tty_str);
static void setup_term(int fd);
static speed_t num2speed(int num);
static void usage(void);

int main(argc, argv)
	int argc;
	char *argv[];
{
	int c, i, j, r;
	int tty_fd;
	int shell_pid, write_pid;
	int count, bytes, offset;
	unsigned char *lp;
	int slot;
	char *pty_fd_str, *tty_str, *check;
	int b_flag, d_flag;

	prog_name= argv[0];
	b_flag= d_flag= 0;
	while (c= getopt(argc, argv, "?bd"), c != -1)
	{
		switch(c)
		{
		case '?':	usage();
		case 'b':	b_flag= 1;	break;
		case 'd':	d_flag= 1;	break;
		default:
			fprintf(stderr, "%s: getopt failed : '%c'\n",
				prog_name, c);
			exit(1);
		}
	}

	if (optind+2 != argc)
		usage();
	pty_fd_str= argv[optind++];
	tty_str= argv[optind++];

	pty_fd= strtol(pty_fd_str, &check, 10);
	if (check[0] != '\0' || pty_fd <= 2)
	{
		fprintf(stderr, "%s: unable to parse pty-fd: '%s'\n", 
			prog_name, pty_fd_str);
		exit(1);
	}

	strict_cr= b_flag;

	openlog(argv[0], LOG_PID, LOG_DAEMON);
	(void) setlogmask(d_flag ? LOG_UPTO(LOG_DEBUG) : LOG_UPTO(LOG_NOTICE));

	do_options();

	tty_fd= open(tty_str, O_RDWR);
	if (tty_fd == -1)
	{
		printf("%s: unable to open '%s': %s\r\n", prog_name, tty_str,
			strerror(errno));
		exit(1);
	}

	slot= fttyslot(tty_fd);

	shell_pid= fork();
	if (shell_pid == -1)
	{
		printf("%s: unable to fork: %s\r\n", prog_name,
			strerror(errno));
		exit(1);
	}
	if (shell_pid == 0)
	{
		close(pty_fd);
		do_child(tty_fd, tty_str);
	}
	close(tty_fd);

	lp= NULL;	/* lint */
	write_pid= fork();
	if (write_pid == -1)
	{
		printf("%s: unable to fork: %s\r\n", prog_name,
			strerror(errno));
		exit(1);
	}
	if (write_pid == 0)
	{
		dup2(pty_fd, 0);
		count= 0;
		for (;;)
		{
			if (!count)
			{
				count= read(0, line, sizeof(line));
				if (count <= 0)
				{
					if (count == -1)
					{
						syslog(LOG_ERR, 
						"error reading from pty: %m");
					}
					break;
				}
				j= 0;
				for (i= 0; i<count; i++)
				{
					c= line[i];
					if (c != '\r' && c != '\n' &&
						c != TC_IAC)
					{
						line2[j++]= c;
						continue;
					}
					if (c == TC_IAC)
					{
						line2[j++]= TC_IAC;
						line2[j++]= TC_IAC;
						continue;
					}
					if (remote_echo)
						line2[j++]= c;
					else
					{
						line2[j++]= '\r';
						line2[j++]= ((c == '\n') ?
							'\n' : '\0');
					}
				}
				count= j;
				lp= line2;
			}
			bytes= write(1, lp, count);
			if (bytes <= 0)
			{
				syslog(LOG_INFO, "network write error: %s",
					bytes == 0 ? "EOF" : strerror(errno));
				break;
			}
			lp += bytes;
			count -= bytes;
		}
		kill(getppid(), SIGKILL);
		_exit(1);
	}

	dup2(pty_fd, 1);
	count= 0;
	offset= initial_count;
	for (;;)
	{
		if (!count)
		{
			count= read(0, line+offset, sizeof(line)-offset);
			if (count <= 0)
			{
				if (count == -1)
				{
					syslog(LOG_INFO,
					"error reading from network: %m");
				}
				break;
			}
			count += offset;
			offset= 0;
			j= 0;
			for(i= 0; i<count; i++)
			{
				c= line[i];
				if (i == 0 && lonely_cr)
				{
					lonely_cr= 0;
					if (c == '\0' || c == '\n')
						continue;
				}
				if (c != '\r' && c != TC_IAC)
				{
					line2[j++]= c;
					continue;
				}
				if (c == '\r')
				{
					i++;
					if (i == count)
					{
						if (strict_cr)
						{
							line[0]= c;
							offset= 1;
							break;
						}
						line2[j++]= '\r';
						lonely_cr= 1;
						continue;
					}
					c= line[i];
					if (c == '\n')
						line2[j++]= c;
					else if (c == '\0')
						line2[j++]= '\r';
					else
					{
						line2[j++]= '\r';
						line2[j++]= c;
					}
				}
				else
				{
					r= do_control(line+i, count-i);
					if (i+r <= count)
					{
						i += r-1;
						continue;
					}

					/* Need more data */
					offset= count-i;
					memmove(line, line+i, offset);
					i= count;
				}
			}
			lp= line2;
			count= j;
			if (!count)
				continue;
		}
		bytes= write(1, lp, count);
		if (bytes <= 0)
		{
			syslog(LOG_ERR, "error writing to pty: %s",
				bytes ? "EOF" : strerror(errno));
			break;
		}
		lp += bytes;
		count -= bytes;
	}
	kill(write_pid, SIGKILL);
	return(0);
}

static void do_options()
{
	size_t buf_off;
	size_t buf_len;
	int o, r, fd, do_read;
	struct option *op;
	struct suboption *osp;
	unsigned char buf[1024];

	fd= 1;	/* Send data to stdout */

	/* Send our options */
	for (op= local_options; op->option >= 0; op++)
	{
		if (!op->state)
			continue;
		buf[0]= TC_IAC;
		buf[1]= TC_WILL;
		buf[2]= op->option;
		write_cmd(fd, buf, 3);
	}
	for (op= remote_options; op->option >= 0; op++)
	{
		if (!op->state)
			continue;
		buf[0]= TC_IAC;
		buf[1]= TC_DO;
		buf[2]= op->option;
		write_cmd(fd, buf, 3);
	}

	/* Wait for incoming options. We need to know about all environment
	 * variables before the login shell can be started.
	 */
	buf_off= 0;
	buf_len= sizeof(buf);
	do_read= 1;
	for (;;)
	{
		if (do_read)
		{
			r= read(0, buf+buf_off, buf_len-buf_off);
			if (r == 0)
			{
				/* Client closed connection. We are done. */
				exit(0);
			}
			if (r == -1)
			{
				/* Got an error, tell client and syslog */
				syslog(LOG_ERR, "read from stdin failed: %m");
				exit(1);
			}
			buf_off += r;
		}
		do_read= 0;
		if (buf[0] != TC_IAC)
		{
			/* Got user data. Try to buffer until option
			 * processing is complete.
			 */
			for (o= 1; o<buf_off; o++)
			{
				if (buf[o] == TC_IAC)
					break;
			}
			syslog(LOG_ERR,
				"should buffer %d bytes of user data", o);
			if (o == buf_off)
			{
				buf_off= 0;
				do_read= 1;
				continue;
			}
			buf_off -= o;
			memmove(buf, buf+o, buf_off);
		}
		if (buf_off < 2)
		{
			do_read= 1;
			continue;
		}
		o= 0;
		switch (buf[1])
		{
		case TC_DONT:
		case TC_DO:
		case TC_WONT:
		case TC_WILL:
			if (buf_off < 3)
			{
				do_read= 1;
				continue;
			}
			process_option(fd, buf[1], buf[2]);
			o= 3;
			break;
		case TC_SB:	/* subnegotiation, try to locate the end */
			if (buf_off < 5)
			{
				do_read= 1;
				continue;
			}
			for (o= 3; o<buf_off; o++)
			{
				if (buf[o] != TC_IAC)
					continue;
				o++;
				if (o >= buf_off)
					break;	/* not enough data */
				if (buf[o] == TC_SE)
					break;	/* found end */
			}
			if (o >= buf_off)
			{
				do_read= 1;
				continue;
			}
			o++;
			for (osp= suboptions; osp->option >= 0; osp++)
			{
				if (osp->option == buf[2])
					break;
			}
			if (osp->option < 0)
			{
				syslog(LOG_ERR,
					"subnegotiation for unknown option %d",
					buf[2]);
				break;
			}
			osp->func(fd, buf[2], buf+3, o-5);
			break;
		default:
			syslog(LOG_ERR, "unknown telnet command %d",
				buf[1]);
			exit(1);
		}
		assert(o);
		buf_off -= o;
		if (buf_off)
			memmove(buf, buf+o, buf_off);
		else
			do_read= 1;
		if (options_done())
			break;
	}
	if (buf_off)
	{
		if (initial_count+buf_off <= sizeof(line))
		{
			memcpy(line+initial_count, buf, buf_off);
			initial_count += buf_off;
		}
	}
}

static int do_control(buf, size)
unsigned char *buf;
size_t size;
{
	int o, r, fd, sig;
	char ch;
	unsigned char cmd;
	struct suboption *osp;
	struct termios tios;

	fd= 0;

	if (size < 2)
		return 2;
	cmd= buf[1];

	switch(cmd)
	{
	case TC_NOP:
	case TC_DM:		/* Should discard user data before DM */
	case TC_GA:
		return 2;
	case TC_BRK:
		sig= SIGQUIT;
#ifdef TIOCSIGP
		r= ioctl(pty_fd, TIOCSIGP, &sig);
		if (r != 0)
			syslog(LOG_ERR, "TIOCSIGP(SIGQUIT) failed: %m");
#endif
		return 2;
	case TC_IP:
		sig= SIGINT;
#ifdef TIOCSIGP
		r= ioctl(pty_fd, TIOCSIGP, &sig);
		if (r != 0)
			syslog(LOG_ERR, "TIOCSIGP(SIGINT) failed: %m");
#endif
		return 2;
	case TC_AYT:
		/* Say something */
		write (0, "\r\n[Yes]\r\n", 9);
		return 2;
	case TC_AO:
	case TC_EC:
	case TC_EL:
		r= ioctl(pty_fd, TCGETS, &tios);
		if (r != 0)
		{
			syslog(LOG_ERR, "TCGETS failed: %m");
			return 2;
		}
		if (cmd == TC_AO)
			ch= tios.c_cc[VDISCARD];
		else if (cmd == TC_EC)
			ch= tios.c_cc[VERASE];
		else if (cmd == TC_EL)
			ch= tios.c_cc[VKILL];
		else
			ch= _POSIX_VDISABLE;
		if (cmd != _POSIX_VDISABLE)
			write(1, &ch, 1);
		return 2;
	case TC_DONT:
	case TC_DO:
	case TC_WONT:
	case TC_WILL:
		if (size < 3)
			return 3;
		process_option(fd, cmd, buf[2]);
		return 3;
	case TC_SB:	/* subnegotiation, try to locate the end */
		if (size < 5)
			return 5;
		for (o= 3; o<size; o++)
		{
			if (buf[o] != TC_IAC)
				continue;
			o++;
			if (o >= size)
				return size+1;	/* not enough data */
			if (buf[o] == TC_SE)
				break;	/* found end */
		}
		if (o >= size)
			return size+1;
		o++;
		for (osp= suboptions; osp->option >= 0; osp++)
		{
			if (osp->option == buf[2])
				break;
		}
		if (osp->option < 0)
		{
			syslog(LOG_ERR,
				"subnegotiation for unknown option %d",
				buf[2]);
			return o;
		}
		osp->func(fd, buf[2], buf+3, o-5);
		return o;
	default:
		syslog(LOG_ERR, "unknown command %d", cmd);
		return 2;
	}
}

static void process_option(int fd, unsigned char cmd, unsigned char option)
{
	int enable;
	struct option *table, *op;
	unsigned char buf[3];

	enable= (cmd == TC_DO || cmd == TC_WILL);
	table= ((cmd == TC_DO || cmd == TC_DONT) ? local_options :
		remote_options);
	for (op= table; op->option >= 0; op++)
	{
		if (op->option == option)
			break;
	}

	if (op->option < 0)
	{
		syslog(LOG_INFO, "unknown option %d, cmd %s",
			option, cmd_name(cmd));
		if (cmd == TC_DONT || cmd == TC_WONT)
		{
			/* Default is off */
			return;
		}
		if (cmd == TC_DO)
		{
			buf[0]= TC_IAC;
			buf[1]= TC_WONT;
			buf[2]= option;
			write_cmd(fd, buf, 3);
			return;
		}
		if (cmd == TC_WILL)
		{
			buf[0]= TC_IAC;
			buf[1]= TC_DONT;
			buf[2]= option;
			write_cmd(fd, buf, 3);
			return;
		}
		syslog(LOG_ERR, "process_option: cmd %d?", cmd);
		exit(1);
	}
	if (!op->state)
	{
		/* Disabled */
		if (!enable)
		{
			/* Keep disabled */
			op->acked= 1;
		}
		else if (!op->func)
		{
			/* Refuse */
			buf[0]= TC_IAC;
			if (cmd == TC_DO)
				buf[1]= TC_WONT;
			else if (cmd == TC_WILL)
				buf[1]= TC_DONT;
			else
			{
				syslog(LOG_ERR, "process_option: cmd %d?",
					cmd);
				exit(1);
			}
			buf[2]= option;
			write_cmd(fd, buf, 3);
			return;
		}
		else
		{
			/* Enable option */
			buf[0]= TC_IAC;
			if (cmd == TC_DO)
				buf[1]= TC_WILL;
			else if (cmd == TC_WILL)
				buf[1]= TC_DO;
			else
			{
				syslog(LOG_ERR, "process_option: cmd %d?",
					cmd);
				exit(1);
			}
			buf[2]= option;
			write_cmd(fd, buf, 3);
			op->state= 1;
			op->acked= 1;
		}
		op->func(fd, option, enable);
		return;
	}
	else
	{
		/* Enabled */
		if (enable)
		{
			/* Keep enabled */
			op->acked= 1;
		}
		else if (op->state > 1)
		{
			/* Failure */
			syslog(LOG_ERR, "client refuses %s option %s (%d)",
				table == local_options ? "local" : "remote",
				op->label, option);
			exit(1);
		}
		else
		{
			/* Disable option */
			op->state= 0;
			op->acked= 1;
		}
		op->func(fd, option, enable);
		return;
	}
}

static char *cmd_name(unsigned char cmd)
{
	switch(cmd)
	{
	case TC_DONT:	return "DON'T";
	case TC_DO:	return "DO";
	case TC_WONT:	return "WON'T";
	case TC_WILL:	return "WILL";
	default:	return "unknown-command";
	}
}

static void write_cmd(fd, buf, size)
int fd;
unsigned char *buf;
size_t size;
{
	int o, r;

	for (o= 0; o<size; o += r)
	{
		r= write(fd, buf+o, size-o);
		if (r == -1 && errno == EINTR)
		{
			r= 0;
			continue;
		}
		if (r <= 0)
		{
			syslog(LOG_ERR, "write to network failed: %s",
				r == 0 ? "EOF" : strerror(errno));
		}
	}
}

static int options_done(void)
{
	struct option *op;
	for (op= local_options; op->option >= 0; op++)
	{
		if (op->acked)
			continue;
		if (!op->state)
			continue;
		return 0;
	}
	for (op= remote_options; op->option >= 0; op++)
	{
		if (op->acked)
			continue;
		if (!op->state)
			continue;
		return 0;
	}
	if (!got_termtype)
	{
		return 0;
	}
	if (!got_xdisploc)
	{
		return 0;
	}
	return 1;
}

static void opt_null(int fd, unsigned char option, int enable)
{
	/* Nothing to do */
}

static void opt_termtype(int fd, unsigned char option, int enable)
{
	unsigned char buf[6];

	if (!enable)
	{
		got_termtype= -1;
		return;
	}
	buf[0]= TC_IAC;
	buf[1]= TC_SB;
	buf[2]= option;
	buf[3]= TO_TT_SB_SEND;
	buf[4]= TC_IAC;
	buf[5]= TC_SE;
	write_cmd(fd, buf, 6);
}

static void opt_termsubtype(int fd, unsigned char option, unsigned char *buf,
	size_t size)
{
	int i;
	unsigned char c;

	if (size < 1 || size >= 256)
	{
		syslog(LOG_ERR, "wrong length for terminal type: %d", size);
		got_termtype= -1;
		return;
	}
	if (buf[0] != TO_TT_SB_IS)
	{
		syslog(LOG_ERR, "wrong command for terminal type: %d", buf[0]);
	}

	/* Convert to lower case. */
	for (i= 1; i<size; i++)
	{
		c= buf[i];
		if (isupper(c))
			buf[i]= tolower(c);
	}
	memcpy(term+5, buf+1, size-1);
	term[5+size-1]= '\0';
	got_termtype= 1;
}

static void opt_termspeed(int fd, unsigned char option, int enable)
{
	unsigned char buf[6];

	if (!enable)
		return;
	buf[0]= TC_IAC;
	buf[1]= TC_SB;
	buf[2]= option;
	buf[3]= TO_TS_SB_SEND;
	buf[4]= TC_IAC;
	buf[5]= TC_SE;
	write_cmd(fd, buf, 6);
}

static void opt_termsubspeed(int fd, unsigned char option, unsigned char *buf,
	size_t size)
{
	unsigned long ispeed, ospeed;
	unsigned char *check;
	struct termios tt;

	if (size < 1 || size >= 256)
	{
		syslog(LOG_ERR, "wrong length for terminal speed: %d", size);
		got_termtype= -1;
		return;
	}
	if (buf[0] != TO_TT_SB_IS)
	{
		syslog(LOG_ERR, "wrong command for terminal speed: %d", buf[0]);
	}

	ospeed= strtoul((char *)buf+1, (char **)&check, 10);
	if (check >= buf+size || check[0] != ',')
	{
		syslog(LOG_ERR, "unable to parse terminal speed '%.*s'",
			size-1, buf+1);
		return;
	}
	ispeed= strtoul((char *)check+1, (char **)&check, 10);
	if (check > buf+size || check[0] != TC_IAC)
	{
		syslog(LOG_ERR, "unable to parse terminal speed '%.*s'",
			size-1, buf+1);
		return;
	}

	term_ispeed= num2speed(ispeed);
	term_ospeed= num2speed(ospeed);
	if (pty_fd != -1)
	{
		tcgetattr(pty_fd, &tt);
		cfsetospeed(&tt, term_ospeed);
		cfsetispeed(&tt, term_ispeed);
		tcsetattr(pty_fd, TCSANOW, &tt);
	}
}

static void opt_xdisploc(int fd, unsigned char option, int enable)
{
	unsigned char buf[6];

	if (!enable)
	{
		got_xdisploc= -1;
		return;
	}
	buf[0]= TC_IAC;
	buf[1]= TC_SB;
	buf[2]= option;
	buf[3]= TO_XDL_SB_SEND;
	buf[4]= TC_IAC;
	buf[5]= TC_SE;
	write_cmd(fd, buf, 6);
}

static void opt_xdisplocsub(int fd, unsigned char option, unsigned char *buf,
	size_t size)
{
	if (size < 1 || size >= 256)
	{
		syslog(LOG_ERR, "wrong length for Xdisplay location: %d", size);
		got_termtype= -1;
		return;
	}
	if (buf[0] != TO_XDL_SB_IS)
	{
		syslog(LOG_ERR,
			"wrong command for X display location type: %d",
			buf[0]);
	}

	memcpy(display+8, buf+1, size-1);
	display[8+size-1]= '\0';
	got_xdisploc= 1;
}

static void opt_naws(int fd, unsigned char option, unsigned char *buf,
	size_t size)
{
	struct winsize winsize;

	if (size < 4)
	{
		syslog(LOG_ERR, "wrong length for window size: %d", size);
		return;
	}
	term_width= (buf[0] << 8) | buf[1];
	term_height= (buf[2] << 8) | buf[3];
	if (pty_fd != -1)
	{
		winsize.ws_row= term_height;
		winsize.ws_col= term_width;
		winsize.ws_xpixel= 0;
		winsize.ws_ypixel= 0;
		ioctl(pty_fd, TIOCSWINSZ, &winsize);
	}
}

static void do_child(tty_fd, tty_str)
int tty_fd;
char *tty_str;
{
	int ctty_fd, tst_fd;
	FILE *tty_file;
	int sav_errno;

	/* Set up the terminal attributes. */
	setup_term(tty_fd);

	/* Let's start the new session. */
	setsid();
	ctty_fd= open(tty_str, O_RDWR);
	if (ctty_fd == -1)
	{
		fprintf(stderr, "%s(do_child): unable to open '%s': %s\r\n",
			prog_name, tty_str, strerror(errno));
		exit(1);
	}
	/* Test if we really got a controlling tty. */
	tst_fd= open("/dev/tty", O_RDWR);
	if (tst_fd == -1)
	{
		fprintf(stderr, 
	"%s(do_child): '%s' didn't result in a controlling tty (%s)\r\n",
			prog_name, tty_str, strerror(errno));
		exit(1);
	}

	/* We reached the point of no return. */
	close(tst_fd);
	close(tty_fd);

	if (ctty_fd != 0)
	{
		dup2(ctty_fd, 0);
		close(ctty_fd);
		ctty_fd= 0;
	}
	dup2(ctty_fd, 1);
	dup2(ctty_fd, 2);

	start_shell();

	sav_errno= errno;
	tty_file= fdopen(2, "w");
	if (tty_file)
	{
		fprintf(tty_file, "%s(do_child): unable to exec shell: %s\r\n",
			prog_name, strerror(sav_errno));
		fflush(tty_file);
	}
	_exit(1);
}

static void setup_term(fd)
int fd;
{
	struct termios tt;
	struct winsize winsize;

	if (term_ospeed || term_ispeed)
	{
		tcgetattr(fd, &tt);
		cfsetospeed(&tt, term_ospeed);
		cfsetispeed(&tt, term_ispeed);
		tcsetattr(fd, TCSANOW, &tt);
	}
	if (term_width || term_height)
	{
		winsize.ws_row= term_height;
		winsize.ws_col= term_width;
		winsize.ws_xpixel= 0;
		winsize.ws_ypixel= 0;
		ioctl(fd, TIOCSWINSZ, &winsize);
	}
}

static speed_t num2speed(num)
int num;
{
	int sp;
	speed_t code;

	static struct 
	{
		int num;
		speed_t value;
	} speed_table[]=
	{
		{ 0, B0, }, { 50, B50, }, { 75, B75, }, { 110, B110, },
		{ 134, B134, }, { 150, B150, }, { 200, B200, }, { 300, B300, },
		{ 600, B600, }, { 1200, B1200, }, { 1800, B1800, },
		{ 2400, B2400, }, { 4800, B4800, }, { 9600, B9600, },
		{ 19200, B19200, }, { 38400, B38400, },
		{ -1, -1 },
	};
	int i;

	/* Use the first higher speed, or else simply the highest speed */
	sp= 0;
	code= B0;
	for (i= 0; speed_table[i].num != -1; i++)
	{
		if (speed_table[i].num == num)
			return (speed_table[i].value);
		if (sp < num)
		{
			if (speed_table[i].num > sp)
			{
				sp= speed_table[i].num;
				code= speed_table[i].value;
			}
		}
		if (sp > num)
		{
			if (speed_table[i].num > num &&
				speed_table[i].num < sp)
			{
				sp= speed_table[i].num;
				code= speed_table[i].value;
			}
		}
	}
	return code;
}

static int start_shell(void)
{
	char namebuf[30];
	char *name, *user, *logname, *home, *shell, **env, *bp;
	char *sh;			/* sh/pw_shell field value */
	char *argx0;			/* argv[0] of the shell */
	int n, ap, i;
	size_t len;
	struct passwd *pwd;
	char *argx[N_ARGS];		/* pw_shell arguments */
	struct stat sb;

	name= getenv("USER");
	if (name != NULL)
	{
		pwd= getpwnam(name);
		if (pwd == NULL)
			fatal("no password file entry for '%s'", name);
	}
	else
	{
		/* Try to get the name based on the user ID */
		pwd= getpwuid(getuid());
		if (pwd == NULL)
		{
			fatal("no password file entry for uid %d?",
				getuid());
		}
		if (strlcpy(namebuf, pwd->pw_name, sizeof(namebuf)) >=
			sizeof(namebuf))
		{
			fatal("login name in password file too long");
		}
		name= namebuf;
	}

	/* Check if the system is going down  */
	if (stat("/etc/nologin", &sb) == 0 && pwd->pw_uid != 0)
	{
		printf("System going down\n\n");
		exit(1);
	}

	/* Create the argv[] array from the pw_shell field. */
	sh= pwd->pw_shell;
	if (strlen(sh) != 0)
	{
		/* Extension: assume that the shell field includes arguments. */

		/* First make a copy of pw_shell. */
		len= strlen(sh)+1;
		bp= os_malloc("start_shell", len);
		strlcpy(bp, sh, len);
		assert(strlen(bp) == len-1);
		sh= bp;
		for (ap= 1; ap < N_ARGS; ap++)
		{
			/* Find end of word */
			while (*bp != '\0' && *bp != ' ' && *bp != '\t')
				bp++;
			if (*bp == '\0')
				break;
			assert (*bp == ' ' || *bp == '\t');

			*bp++ = '\0';	/* mark end of string */

			/* Skip additional spaces */
			while (*bp == ' ' || *bp == '\t')
				bp++;
			argx[ap] = bp;
		}
		if (ap == N_ARGS)
			fatal("too many arguments in '%s'", pwd->pw_shell);
	}
	else
	{
		sh= "/bin/sh";
		ap= 1;
	}
	assert(ap < N_ARGS);
	argx[ap]= NULL;

	/* Set argv[0] to the name of the shell preceded by a hyphen */
	bp= strrchr(sh, '/');
	if (bp == NULL)
		bp= sh;
	else
		bp++;
	len= 1+strlen(bp)+1;
	argx0= os_malloc("start_shell", len);
	strlcpy(argx0, "-", len);
	strlcat(argx0, bp, len);
	assert(strlen(argx0) == len-1);
	argx[0]= argx0;

	env= os_malloc("start_shell", 7 * sizeof(*env));

	user= concatstr("USER=", name);
	logname= concatstr("LOGNAME=", name);
	home= concatstr("HOME=", pwd->pw_dir);
	shell= concatstr("SHELL=", sh);

	env[0]= user;
	env[1]= logname;
	env[2]= home;
	env[3]= shell;
	env[4]= term;
	i= 5;
	if (got_xdisploc > 0)
		env[i++]= display;
	env[i]= NULL;
	assert(i < 7);

	/* Show the message-of-the-day. */
	show_file(PATH_MOTD);

	/* cd $HOME */
	chdir(pwd->pw_dir);

	/* Reset signals to default values. */
	for (n = 1; n <= _NSIG; ++n)
		signal(n, SIG_DFL);

	/* Execute the user's shell. */
	execve(sh, argx, env);

	fprintf(stderr, "login: can't execute %s: %s\n", sh, strerror(errno));
	exit(1);

	return(0);
}

static char *concatstr(char *str1, char *str2)
{
	char *str;
	size_t len;

	len= strlen(str1)+strlen(str2)+1;
	str= os_malloc("concatstr", len);
	strlcpy(str, str1, len);
	strlcat(str, str2, len);
	assert(strlen(str)+1 == len);

	return str;
}

static void show_file(filename)
char *filename;
{
	/* Read a textfile and show it on the desired terminal. */
	register int fd, len;
	char buf[80];

	fd= open(filename, O_RDONLY);
	if (fd == -1)
		fatal("unable to open '%s': %s", filename, strerror(errno));
	for(;;)
	{
		len = read(fd, buf, 80);
		if (len == 0)
			break;
		if (len == -1)
		{
			fatal("error reading from '%s': %s",
				filename, strerror(errno));
		}

		/* Ignore write errors */
		(void) write(1, buf, len);
	}
	close(fd);
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\r\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: ssctelnetd [-bd] <pty-fd> <tty-name>\n");
	exit(1);
}


/*
 * $PchId: ssctelnetd.c,v 1.3 2011/12/25 12:33:27 philip Exp $
 */
