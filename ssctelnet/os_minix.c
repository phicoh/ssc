/*
os_posix.c

Created:	Dec 2011 by Philip Homburg
*/

#include "os.h"
#include "telnet.h"

#include <termios.h>

#include "ssctelnet.h"

static enum { LS_NORM, LS_BOL, LS_ESC } line_state= LS_BOL;
static int g_p_out= -1;

static void keyboard(int p_out);
static void send_brk(int p_out);
static void screen(int p_in, int p_out);
static void handle_sigwinch(int p_out);
static void do_usr2(int sig);

void do_inout(int p_in, int p_out)
{
	int pid, ppid;
	struct termios termios;

	g_p_out= p_out;

	signal(SIGUSR2, do_usr2);

	ppid= getpid();
	pid= fork();
	switch(pid)
	{
	case 0:
		tcgetattr(0, &termios);
		screen(p_in, p_out);
		ppid= getppid();
		tcsetattr(0, TCSANOW, &termios);
		if (ppid != -1)
			kill(ppid, SIGUSR2);
		break;
	case -1:
		fatal("fork failed: %s\r", strerror(errno));
		break;
	default:
		keyboard(p_out);
		break;
	}
}

void add_rem_output(char *buffer, int buf_size)
{
	if (write(g_p_out, buffer, buf_size) != buf_size)
	{
		fatal("add_rem_output: write failed");
	}
}

int add_output(char *buffer, int buf_size)
{
	return writeall(g_p_out, buffer, buf_size);
}

static void keyboard(int p_out)
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
					send_brk(p_out);
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

static void send_brk(int p_out)
{
	int r;
	unsigned char buffer[2];

	buffer[0]= TC_IAC;
	buffer[1]= TC_BRK;

	r= writeall(p_out, (char *)buffer, 2);
	if (r == -1)
		fatal("Error writing to TCP connection: %s", strerror(errno));
}

static void screen(int p_in, int p_out)
{
	char buffer[1024], *bp, *iacptr;
	int count, optsize;

	for (;;)
	{
		if (do_sigwinch)
		{
			handle_sigwinch(p_out);
			continue;
		}
		count= read (p_in, buffer, sizeof(buffer));
		if (count <0)
		{
			if (errno == EINTR)
				continue;
			perror ("read");
			return;
		}
		if (!count)
			return;
		bp= buffer;
		do
		{
			iacptr= memchr (bp, TC_IAC, count);
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

static void handle_sigwinch(int p_out)
{
	int i, j, r;
	unsigned char buf[3 /* IAC SB NAWS */ + 4*2 /* 4 size bytes,
		optionally doubled */ + 2 /* IAC SE */];
	unsigned char data[4];
	struct winsize wins;

	do_sigwinch= 0;

	r= ioctl(0, TIOCGWINSZ, &wins);
	if (r == -1 && errno == ENOTTY)
	{
		r= ioctl(1, TIOCGWINSZ, &wins);
		if (r == -1)
		{
			perror("TIOCGWINSZ");
			return;
		}
	}
	data[0]= wins.ws_col >> 8;
	data[1]= wins.ws_col & 0xff;
	data[2]= wins.ws_row >> 8;
	data[3]= wins.ws_row & 0xff;

	i= 0;
	buf[i++]= TC_IAC;
	buf[i++]= TC_SB;
	buf[i++]= TELOPT_NAWS;
	for (j= 0; j<sizeof(data); j++)
	{
		if (data[j] == TC_IAC)
			buf[i++]= TC_IAC;
		buf[i++]= data[j];
	}
	buf[i++]= TC_IAC;
	buf[i++]= TC_SE;
	assert(i <= sizeof(buf));
	r= write(p_out, buf, i);
	if (r == -1)
		perror("write");
	else if (r != i)
		fprintf(stderr, "write to network not atomic\r\n");
}
  
static void do_usr2(int sig)
{
	/* 'screen' wants to exit. */
	exit(1);
}

/*
 * $PchId: os_minix.c,v 1.2 2012/01/27 15:56:37 philip Exp philip $
 */
