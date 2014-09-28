/*
ssctelnet.c (based on ttn.c)

Client for the telnet protocol over a secure connection

Created:	March 2005 by Philip Homburg for NAH6
*/

#ifndef _POSIX_SOURCE
#define _POSIX_SOURCE 1
#endif

#include "../include/os.h"

#include <termios.h>

#include "ttn.h"

#define SSCCLIENT_PATH	"/usr/local/sbin/sscclient"

#define SERVICE "telnet"

#define N_ARGS		9

static int p_in, p_out;
static pid_t client_pid;

static void start_client(char *hostname, char *user, char *options);
static void read_greeting(void);
static void screen(void);
static void keyboard(void);
static void send_brk(void);
static int process_opt (char *bp, int count);
static void do_option (int optsrt);
static void dont_option (int optsrt);
static void will_option (int optsrt);
static void wont_option (int optsrt);
static int writeall (int fd, char *buffer, int buf_size);
static int sb_termtype (char *sb, int count);
static void do_usr2(int sig);
static void fatal(char *fmt, ...);
static void usage(void);

static char *prog_name;
static char *term_env;
static int esc_char= '~';
static enum { LS_NORM, LS_BOL, LS_ESC } line_state= LS_BOL;

int main(int argc, char *argv[])
{
	int pid, ppid;
	int c;
	struct termios termios;
	char *hostname, *user, *options;
	char *e_arg, *l_arg, *o_arg;

	(prog_name=strrchr(argv[0],'/')) ? prog_name++ : (prog_name=argv[0]);

	e_arg= o_arg= l_arg= NULL;
	while (c= getopt(argc, argv, "e:l:o:?"), c != -1)
	{
		switch(c)
		{
		case '?': usage();
		case 'e': e_arg= optarg; break;
		case 'l': l_arg= optarg; break;
		case 'o': o_arg= optarg; break;
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	if (optind >= argc)
		usage();
	hostname= argv[optind++];
	if (optind != argc)
		usage();

	if (e_arg)
	{
		switch(strlen(e_arg))
		{
		case 0: esc_char= -1; break;
		case 1: esc_char= e_arg[0]; break;
		default: fatal("Invalid escape character '%s'", e_arg);
		}
	}

	user= l_arg;
	options= o_arg;

	start_client(hostname, user, options);
	read_greeting();

	signal(SIGUSR2, do_usr2);

	ppid= getpid();
	pid= fork();
	switch(pid)
	{
	case 0:
		tcgetattr(0, &termios);
		screen();
		ppid= getppid();
		if (ppid != -1)
			kill(ppid, SIGUSR2);
		tcsetattr(0, TCSANOW, &termios);
		break;
	case -1:
		fprintf(stderr, "%s: fork failed: %s\r\n", argv[0],
			strerror(errno));
		exit(1);
		break;
	default:
		keyboard();
		break;
	}
	exit(0);
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

static void screen()
{
	char buffer[1024], *bp, *iacptr;
	int count, optsize;

	for (;;)
	{
		count= read (p_in, buffer, sizeof(buffer));
		if (count <0)
		{
			perror ("read");
			return;
		}
		if (!count)
			return;
		bp= buffer;
		do
		{
			iacptr= memchr (bp, IAC, count);
			if (!iacptr)
			{
				write(1, bp, count);
				count= 0;
			}
			if (iacptr && iacptr>bp)
			{
				write(1, bp, iacptr-bp);
				count -= (iacptr-bp);
				bp= iacptr;
				continue;
			}
			if (iacptr)
			{
				assert(iacptr == bp);
				optsize= process_opt(bp, count);
				if (optsize<0)
					return;
				assert(optsize);
				bp += optsize;
				count -= optsize;
			}
		} while (count);
	}
}

static void keyboard()
{
	char c, buffer[1024];
	int count;

	for (;;)
	{
		count= read (0, buffer, 1 /* sizeof(buffer) */);
		if (count == -1)
			fatal("Read: %s\r\n", strerror(errno));
		if (!count)
			return;

		if (line_state != LS_NORM)
		{
			c= buffer[0];
			if (line_state == LS_BOL)
			{
				if (c == esc_char)
				{
					line_state= LS_ESC;
					continue;
				}
				line_state= LS_NORM;
			}
			else if (line_state == LS_ESC)
			{
				line_state= LS_NORM;
				if (c == '.')
					return;
				if (c == '#')
				{
					send_brk();
					continue;
				}

				/* Not a valid command or a repeat of the
				 * escape char
				 */
				if (c != esc_char)
				{
					c= esc_char;
					write(p_out, &c, 1);
				}
			}
		}
		if (buffer[0] == '\n')
			write(p_out, "\r", 1);
		count= write(p_out, buffer, count);
		if (buffer[0] == '\r')
		{
			line_state= LS_BOL;
			write(p_out, "\0", 1);
		}
		if (count<0)
		{
			perror("write");
			fprintf(stderr, "errno= %d\r\n", errno);
			return;
		}
		if (!count)
			return;
	}
}

static void send_brk(void)
{
	int r;
	unsigned char buffer[2];

	buffer[0]= IAC;
	buffer[1]= IAC_BRK;

	r= writeall(p_out, (char *)buffer, 2);
	if (r == -1)
		fatal("Error writing to TCP connection: %s", strerror(errno));
}

#define next_char(var) \
	if (offset<count) { (var) = bp[offset++]; } \
	else if (read(p_in, (char *)&(var), 1) <= 0) \
	{ perror ("read"); return -1; }

static int process_opt (char *bp, int count)
{
	unsigned char iac, command, optsrt, sb_command;
	int offset, result;

	offset= 0;
	assert (count);
	next_char(iac);
	assert (iac == IAC);
	next_char(command);
	switch(command)
	{
	case IAC_NOP:
		break;
	case IAC_DataMark:
		/* Ought to flush input queue or something. */
		break;
	case IAC_BRK:
		break;
	case IAC_IP:
		break;
	case IAC_AO:
		break;
	case IAC_AYT:
		break;
	case IAC_EC:
		break;
	case IAC_EL:
		break;
	case IAC_GA:
		break;
	case IAC_SB:
		next_char(sb_command);
		switch (sb_command)
		{
		case OPT_TERMTYPE:
			result= sb_termtype(bp+offset, count-offset);
			if (result<0)
				return result;
			else
				return result+offset;
		default:
			for (;;)
			{
				next_char(iac);
				if (iac != IAC)
					continue;
				next_char(optsrt);
				if (optsrt == IAC)
					continue;
				break;
			}
		}
		break;
	case IAC_WILL:
		next_char(optsrt);
		will_option(optsrt);
		break;
	case IAC_WONT:
		next_char(optsrt);
		wont_option(optsrt);
		break;
	case IAC_DO:
		next_char(optsrt);
		do_option(optsrt);
		break;
	case IAC_DONT:
		next_char(optsrt);
		dont_option(optsrt);
		break;
	case IAC:
		break;
	default:
		break;
	}
	return offset;
}

static void do_option (int optsrt)
{
	unsigned char reply[3];
	int result;

	switch (optsrt)
	{
	case OPT_TERMTYPE:
		if (WILL_terminal_type)
			return;
		if (!WILL_terminal_type_allowed)
		{
			reply[0]= IAC;
			reply[1]= IAC_WONT;
			reply[2]= optsrt;
		}
		else
		{
			WILL_terminal_type= TRUE;
			term_env= getenv("TERM");
			if (!term_env)
				term_env= "unknown";
			reply[0]= IAC;
			reply[1]= IAC_WILL;
			reply[2]= optsrt;
		}
		break;
	default:
		reply[0]= IAC;
		reply[1]= IAC_WONT;
		reply[2]= optsrt;
		break;
	}
	result= writeall(p_out, (char *)reply, 3);
	if (result<0)
		perror("write");
}

static void will_option (int optsrt)
{
	unsigned char reply[3];
	int result;

	switch (optsrt)
	{
	case OPT_ECHO:
		if (DO_echo)
			break;
		if (!DO_echo_allowed)
		{
			reply[0]= IAC;
			reply[1]= IAC_DONT;
			reply[2]= optsrt;
		}
		else
		{
			struct termios termios;

			tcgetattr(0, &termios);
			termios.c_iflag &= ~(ICRNL|IGNCR|INLCR|IXON|IXOFF);
			termios.c_oflag &= ~(OPOST);
			termios.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN|ISIG);
			tcsetattr(0, TCSANOW, &termios);

			DO_echo= TRUE;
			reply[0]= IAC;
			reply[1]= IAC_DO;
			reply[2]= optsrt;
		}
		result= writeall(p_out, (char *)reply, 3);
		if (result<0)
			perror("write");
		break;
	case OPT_SUPP_GA:
		if (DO_suppress_go_ahead)
			break;
		if (!DO_suppress_go_ahead_allowed)
		{
			reply[0]= IAC;
			reply[1]= IAC_DONT;
			reply[2]= optsrt;
		}
		else
		{
			DO_suppress_go_ahead= TRUE;
			reply[0]= IAC;
			reply[1]= IAC_DO;
			reply[2]= optsrt;
		}
		result= writeall(p_out, (char *)reply, 3);
		if (result<0)
			perror("write");
		break;
	default:
		reply[0]= IAC;
		reply[1]= IAC_DONT;
		reply[2]= optsrt;
		result= writeall(p_out, (char *)reply, 3);
		if (result<0)
			perror("write");
		break;
	}
}

static int writeall (fd, buffer, buf_size)
int fd;
char *buffer;
int buf_size;
{
	int result;

	while (buf_size)
	{
		result= write (fd, buffer, buf_size);
		if (result <= 0)
			return -1;
		buffer += result;
		buf_size -= result;
	}
	return 0;
}

static void dont_option (int optsrt)
{
	switch (optsrt)
	{
	default:
		break;
	}
}

static void wont_option (int optsrt)
{
	switch (optsrt)
	{
	default:
		break;
	}
}

static int sb_termtype (char *bp, int count)
{
	unsigned char command, iac, optsrt;
	unsigned char buffer[4];
	int offset, result;

	offset= 0;
	next_char(command);
	if (command == TERMTYPE_SEND)
	{
		buffer[0]= IAC;
		buffer[1]= IAC_SB;
		buffer[2]= OPT_TERMTYPE;
		buffer[3]= TERMTYPE_IS;
		result= writeall(p_out, (char *)buffer,4);
		if (result<0)
			return result;
		count= strlen(term_env);
		if (!count)
		{
			term_env= "unknown";
			count= strlen(term_env);
		}
		result= writeall(p_out, term_env, count);
		if (result<0)
			return result;
		buffer[0]= IAC;
		buffer[1]= IAC_SE;
		result= writeall(p_out, (char *)buffer,2);
		if (result<0)
			return result;

	}
	else
	{
		fprintf(stderr, "got an unknown command (skipping)\r\n");
	}
	for (;;)
	{
		next_char(iac);
		if (iac != IAC)
			continue;
		next_char(optsrt);
		if (optsrt == IAC)
			continue;
		if (optsrt != IAC_SE)
		{
			fprintf(stderr, "got IAC %d\r\n", optsrt);
		}
		break;
	}
	return offset;
}

static void do_usr2(int sig)
{
	/* 'screen' wants to exit. */
	exit(1);
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog_name);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
"Usage: ssctelnet [-e esc-char] [-l <rem-user>] [-o <options>] host\n");
	exit(1);
}

/*
 * $PchId: ssctelnet.c,v 1.2 2005/06/01 10:15:32 philip Exp $
 */
