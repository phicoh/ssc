/*
ssctelnet.c (based on ttn.c)

Client for the telnet protocol over a secure connection

Created:	March 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/telnet.h"

#include <termios.h>

#include "ttn.h"
#include "ssctelnet.h"

#define SSCCLIENT_PATH	"/usr/local/sbin/sscclient"

#define SERVICE "telnet"

#define N_ARGS		9

int esc_char= '~';
int do_sigwinch= 0;

static pid_t client_pid;

static void start_client(char *hostname, char *user, char *options,
	int *p_inp, int *p_outp);
static void read_greeting(int p_in);
static void do_option (int optsrt);
static void dont_option (int optsrt);
static void will_option (int optsrt);
static void wont_option (int optsrt);
static int sb_termtype (char *sb, int count);
static void got_sigwinch(int sig);
static void got_sigalrm(int sig);
static void usage(void);

static char *prog_name;
static char *term_env;

int main(int argc, char *argv[])
{
	int c, p_in, p_out;
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

	start_client(hostname, user, options, &p_in, &p_out);
	read_greeting(p_in);
	do_inout(p_in, p_out);

	exit(0);
}

static void start_client(char *hostname, char *user, char *options,
	int *p_inp, int *p_outp)
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
		*p_inp= fds_out[0];	/* Output from sscclient */
		close(fds_out[1]);
		*p_outp= fds_in[1];	/* Input for sscclient */
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

static void read_greeting(int p_in)
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

#define next_char(var) \
	if (offset<count) { (var) = bp[offset++]; } \
	else return 0;

int process_opt (char *bp, int count)
{
	unsigned char iac, command, optsrt, sb_command;
	int offset, result;

	offset= 0;
	assert (count);
	next_char(iac);
	assert (iac == TC_IAC);
	next_char(command);
	switch(command)
	{
	case TC_NOP:
		break;
	case TC_DM:
		/* Ought to flush input queue or something. */
		break;
	case TC_BRK:
		break;
	case TC_IP:
		break;
	case TC_AO:
		break;
	case TC_AYT:
		break;
	case TC_EC:
		break;
	case TC_EL:
		break;
	case TC_GA:
		break;
	case TC_SB:
		next_char(sb_command);
		switch (sb_command)
		{
		case TELOPT_TERMINAL_TYPE:
			result= sb_termtype(bp+offset, count-offset);
			if (result<0)
				return result;
			else
				return result+offset;
		default:
			for (;;)
			{
				next_char(iac);
				if (iac != TC_IAC)
					continue;
				next_char(optsrt);
				if (optsrt == TC_IAC)
					continue;
				break;
			}
		}
		break;
	case TC_WILL:
		next_char(optsrt);
		will_option(optsrt);
		break;
	case TC_WONT:
		next_char(optsrt);
		wont_option(optsrt);
		break;
	case TC_DO:
		next_char(optsrt);
		do_option(optsrt);
		break;
	case TC_DONT:
		next_char(optsrt);
		dont_option(optsrt);
		break;
	case TC_IAC:
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
	struct sigaction sa;

	switch (optsrt)
	{
	case TELOPT_TERMINAL_TYPE:
		if (WILL_terminal_type)
			return;
		if (!WILL_terminal_type_allowed)
		{
			reply[0]= TC_IAC;
			reply[1]= TC_WONT;
			reply[2]= optsrt;
		}
		else
		{
			WILL_terminal_type= TRUE;
			term_env= getenv("TERM");
			if (!term_env)
				term_env= "unknown";
			reply[0]= TC_IAC;
			reply[1]= TC_WILL;
			reply[2]= optsrt;
		}
		break;
	case TELOPT_NAWS:
		if (WILL_naws)
			return;
		if (!WILL_naws_allowed)
		{
			reply[0]= TC_IAC;
			reply[1]= TC_WONT;
			reply[2]= optsrt;
		}
		else
		{
			WILL_naws= TRUE;
			reply[0]= TC_IAC;
			reply[1]= TC_WILL;
			reply[2]= optsrt;

			/* Set SIGWINCH handler and trigger sending of
			 * current window size. Also set SIGALRM handler
			 * to handle race conditions.
			 */
			sa.sa_handler= got_sigwinch;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags= 0;
			if (sigaction(SIGWINCH, &sa, NULL) == -1)
				perror("sigaction");
			sa.sa_handler= got_sigalrm;
			if (sigaction(SIGALRM, &sa, NULL) == -1)
				perror("sigaction");
			do_sigwinch= 1;
		}
  		break;
	default:
		reply[0]= TC_IAC;
		reply[1]= TC_WONT;
		reply[2]= optsrt;
		break;
	}
	add_rem_output((char *)reply, 3);
}

static void will_option (int optsrt)
{
	unsigned char reply[3];
	int result;

	switch (optsrt)
	{
	case TELOPT_ECHO:
		if (DO_echo)
			break;
		if (!DO_echo_allowed)
		{
			reply[0]= TC_IAC;
			reply[1]= TC_DONT;
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
			reply[0]= TC_IAC;
			reply[1]= TC_DO;
			reply[2]= optsrt;
		}
		add_rem_output((char *)reply, 3);
		break;
	case TELOPT_SUP_GO_AHEAD:
		if (DO_suppress_go_ahead)
			break;
		if (!DO_suppress_go_ahead_allowed)
		{
			reply[0]= TC_IAC;
			reply[1]= TC_DONT;
			reply[2]= optsrt;
		}
		else
		{
			DO_suppress_go_ahead= TRUE;
			reply[0]= TC_IAC;
			reply[1]= TC_DO;
			reply[2]= optsrt;
		}
		add_rem_output((char *)reply, 3);
		break;
	default:
		reply[0]= TC_IAC;
		reply[1]= TC_DONT;
		reply[2]= optsrt;
		add_rem_output((char *)reply, 3);
		break;
	}
}

int writeall (fd, buffer, buf_size)
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
	if (command == TO_TT_SB_SEND)
	{
		buffer[0]= TC_IAC;
		buffer[1]= TC_SB;
		buffer[2]= TELOPT_TERMINAL_TYPE;
		buffer[3]= TO_TT_SB_IS;
		add_rem_output((char *)buffer,4);
		count= strlen(term_env);
		if (!count)
		{
			term_env= "unknown";
			count= strlen(term_env);
		}
		add_rem_output(term_env, count);
		buffer[0]= TC_IAC;
		buffer[1]= TC_SE;
		add_rem_output((char *)buffer,2);
	}
	else
	{
		fprintf(stderr, "got an unknown command (skipping)\r\n");
	}
	for (;;)
	{
		next_char(iac);
		if (iac != TC_IAC)
			continue;
		next_char(optsrt);
		if (optsrt == TC_IAC)
			continue;
		if (optsrt != TC_SE)
		{
			fprintf(stderr, "got TC_IAC %d\r\n", optsrt);
		}
		break;
	}
	return offset;
}

static void got_sigwinch(int sig)
{
	do_sigwinch= 1;

	/* Set alarm to recover from a potential race condition */
	alarm(1);
}

static void got_sigalrm(int sig)
{
	if (do_sigwinch)
	{
		printf("got_sigalrm: alarm for do_sigwinch\r\n");
		alarm(1);
	}
}

void fatal(char *fmt, ...)
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
 * $PchId: ssctelnet.c,v 1.5 2012/01/27 15:57:32 philip Exp $
 */
