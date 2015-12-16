/*
os_posix.c

Created:	Dec 2011 by Philip Homburg
*/

#include "os.h"
#include "telnet.h"

#include <termios.h>

#include "ssctelnet.h"

static enum { LS_NORM, LS_BOL, LS_ESC } line_state= LS_BOL;
static size_t locout_offset, locout_size, locout_max;
static char *locout_buf;
static size_t remout_next_size, remout_next_max;
static char *remout_next_buf;

static void keyboard(int *eofp);
static void screen(int p_in, int *eofp);
static void handle_sigwinch(void);
static void do_usr2(int sig);

void do_inout(int p_in, int p_out)
{
	int r, loc_eof, rem_eof, max_fd;
	fd_set in_set, out_set;
	size_t remout_offset, remout_size;
	char *remout_buf;
	struct termios termios;

	fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK);
	fcntl(p_in, F_SETFL, fcntl(p_in, F_GETFL) | O_NONBLOCK);
	fcntl(p_out, F_SETFL, fcntl(p_out, F_GETFL) | O_NONBLOCK);

	loc_eof= 0;
	rem_eof= 0;

	max_fd= p_in;
	if (p_out > max_fd)
		max_fd= p_out;

	locout_offset= locout_size= locout_max= 0;
	locout_buf= NULL;
	remout_offset= remout_size= 0;
	remout_buf= NULL;
	remout_next_size= remout_next_max= 0;
	remout_next_buf= NULL;

	tcgetattr(0, &termios);
	while (!rem_eof)
	{
		if (do_sigwinch)
		{
			handle_sigwinch();
			continue;
		}

		FD_ZERO(&in_set);
		FD_ZERO(&out_set);

		if (remout_offset < remout_size ||
			remout_next_size > 0)
		{
			FD_SET(p_out, &out_set);
		}
		else if (loc_eof)
		{
			if (p_out != -1)
			{
				close(p_out);
				p_out= -1;
			}
		}
		else
			FD_SET(0, &in_set);

		if (locout_offset < locout_size)
			FD_SET(1, &out_set);
		else if (rem_eof)
			;	/* Nothing */
		else
			FD_SET(p_in, &in_set);

		r= select(max_fd+1, &in_set, &out_set, NULL, NULL);
		if (r == -1)
		{
			if (errno == EINTR)
				continue;
			fatal("select failed: %s", strerror(errno));
		}
		else if (r == 0)
			fatal("select return 0");

		if (FD_ISSET(0, &in_set))
		{
			keyboard(&loc_eof);

			/* Trigger write */
			if (remout_next_size > 0)
				FD_SET(p_out, &out_set);
		}
		if (FD_ISSET(p_out, &out_set))
		{
			if (remout_offset >= remout_size && remout_next_size)
			{
				free(remout_buf);
				remout_offset= 0;
				remout_size= remout_next_size;
				remout_buf= remout_next_buf;
				remout_next_size= 0;
				remout_next_max= 0;
				remout_next_buf= NULL;
			}
			assert(remout_offset < remout_size);
			r= write(p_out, remout_buf+remout_offset,
				remout_size-remout_offset);
			if (r <= 0)
			{
				fatal("error sending data to server: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			remout_offset += r;
		}
		if (FD_ISSET(p_in, &in_set))
		{
			screen(p_in, &rem_eof);

			/* Trigger write */
			if (locout_size > 0)
				FD_SET(1, &out_set);
		}
		if (FD_ISSET(1, &out_set))
		{
			assert(locout_offset < locout_size);
			r= write(1, locout_buf+locout_offset,
				locout_size-locout_offset);
			if (r <= 0)
			{
				if (errno == EAGAIN)
					continue;
				fatal("error sending data to stdout: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			locout_offset += r;
			if (locout_offset == locout_size)
			{
				locout_offset= locout_size= 0;
			}
		}
	}
	tcsetattr(0, TCSANOW, &termios);
#if 0
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
		if (ppid != -1)
			kill(ppid, SIGUSR2);
		tcsetattr(0, TCSANOW, &termios);
		break;
	case -1:
		fatal("fork failed: %s\r", strerror(errno));
		break;
	default:
		keyboard(p_out);
		break;
	}
#endif
}

void add_rem_output(char *buffer, int buf_size)
{
	if (remout_next_size + buf_size > remout_next_max)
	{
		remout_next_max= 2*remout_next_max + buf_size + 10;
		remout_next_buf= os_realloc("ssctelnet", remout_next_buf,
			remout_next_max);
	}
	memcpy(&remout_next_buf[remout_next_size], buffer, buf_size);
	remout_next_size += buf_size;
}

static void add_loc_output(char *buffer, int buf_size)
{
	assert(locout_offset == 0);
	if (locout_size + buf_size > locout_max)
	{
		locout_max= 2*locout_max + buf_size + 10;
		locout_buf= os_realloc("ssctelnet", locout_buf,
			locout_max);
	}
	memcpy(&locout_buf[locout_size], buffer, buf_size);
	locout_size += buf_size;
}

static void keyboard(int *eofp)
{
	char c, buffer[1024];
	int count, offset;

	count= read(0, buffer, sizeof(buffer));
	if (count == -1)
		fatal("Read: %s\r\n", strerror(errno));
	if (!count)
	{
		*eofp= 1;
		return;
	}

	for (offset= 0; offset < count; offset++)
	{
		c= buffer[offset];
		if (line_state != LS_NORM)
		{
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
				{
					*eofp= 1;
					return;
				}
				if (c == '#')
				{
					c= TC_IAC;
					add_rem_output(&c, 1);
					c= TC_BRK;
					add_rem_output(&c, 1);
					continue;
				}

				/* Not a valid command or a repeat of the
				 * escape char
				 */
				if (c != esc_char)
				{
					c= esc_char;
					add_rem_output(&c, 1);
				}
			}
		}
		if (c == '\n')
			add_rem_output("\r", 1);
		add_rem_output(&c, 1);
		if (c == '\r')
		{
			line_state= LS_BOL;
			add_rem_output("\0", 1);
		}
	}
}

static void screen(int p_in, int *eofp)
{
	char buffer[1024], *bp, *iacptr;
	int count, optsize;

	for (;;)
	{
		count= read(p_in, buffer, sizeof(buffer));
		if (count == -1)
		{
			if (errno == EAGAIN)
				return;
			fatal("read from p_in failed: %s", strerror(errno));
		}
		if (!count)
		{
			*eofp= 1;
			return;
		}
		bp= buffer;
		do
		{
			iacptr= memchr (bp, TC_IAC, count);
			if (!iacptr)
			{
				add_loc_output(bp, count);
				count= 0;
			}
			if (iacptr && iacptr>bp)
			{
				add_loc_output(bp, iacptr-bp);
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

static void handle_sigwinch()
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
	add_rem_output(buf, i);
}
  
static void do_usr2(int sig)
{
	/* 'screen' wants to exit. */
	exit(1);
}

/*
 * $PchId: os_posix.c,v 1.1 2012/01/26 19:50:31 philip Exp philip $
 */
