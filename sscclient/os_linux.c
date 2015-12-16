/*
os_linux.c

Operating specific functions for Linux

Created:	Nov 2008 by Philip Homburg
*/

#include "../include/config.h"
#include "../include/os.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <termios.h>

#include "sscclient.h"


#define CHILD_TO	30	/* Check this often whether the child is 
				 * still alive.
				 */

static pid_t child_pid;

static void do_in(void);
static void do_alarm(int sig);
static void kill_parent(int sig);

#if USE_GETADDRINFO
int tcp_connect(char *servername)
{
	int e, i, r, fd;
	in_port_t remport;
	char *servicename;
	const char *str;
	struct addrinfo *aie, *aip;
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;
	struct addrinfo hints;
	union
	{
		char str4[INET_ADDRSTRLEN];
		char str6[INET6_ADDRSTRLEN];
	} buf;

#if USE_TCPMUX
	servicename= "tcpmux";
#else
	servicename= SSC_PROTO_NAME;
#endif

	memset(&hints, '\0', sizeof(hints));
	r= getaddrinfo(servername, servicename, &hints, &aip);
	if (r != 0)
		fatal("unknown hostname '%s': %s", servername, gai_strerror(r));

	fd= -1;	/* lint */
	for (aie= aip; aie != NULL; aie= aie->ai_next)
	{
		fd= socket(aie->ai_family, aie->ai_socktype, aie->ai_protocol);
		if (fd == -1)
		{
			freeaddrinfo(aip);
			return fd;
		}
		if (connect(fd, (struct sockaddr *)aie->ai_addr,
			aie->ai_addrlen) != 0)
		{
			e= errno;
			close(fd);

			switch(aie->ai_family)
			{
			case AF_INET:
				sin4= (struct sockaddr_in *)aie->ai_addr;
				str= inet_ntop(AF_INET, &sin4->sin_addr,
					(char *)&buf, sizeof(buf));
				remport= sin4->sin_port;
				break;
			case AF_INET6:
				sin6= (struct sockaddr_in6 *)aie->ai_addr;
				str= inet_ntop(AF_INET6, &sin6->sin6_addr,
					(char *)&buf, sizeof(buf));
				remport= sin6->sin6_port;
				break;
			default:
				str= NULL;
				remport= 0;
				break;
			}
			if (aie->ai_next != NULL)
			{
				/* More addresses, ignore the error */
				fprintf(stderr,
				"Warning: unable to connect to [%s]:%u: %s\n",
					str ? str : "???", ntohs(remport),
					strerror(e));
				continue;
			}
			/* Last address, fatal error */
			fatal("cannot connect to [%s]:%u: %s",
				str ? str : "???", ntohs(remport),
				strerror(e));
		}

		/* Success */
		freeaddrinfo(aip);
		break;
	}

	return fd;

}
#else /* !USE_GETADDRINFO */
int tcp_connect(char *servername)
{
	char *servicename;
	struct hostent *he;
	struct servent *se;
	struct in_addr hostaddr;
	in_port_t remport;
	int e, i, fd;
	struct sockaddr_in sin;

#if USE_TCPMUX
	servicename= "tcpmux";
	se= getservbyname(servicename, "tcp");
	if (se == NULL)
		fatal("unable to lookup port for service '%s'\n", servicename);
	remport= se->s_port;
#else
	servicename= SSC_PROTO_NAME;
	se= getservbyname(servicename, "tcp");
	if (se == NULL)
		fatal("unable to lookup port for service '%s'\n", servicename);
	remport= se->s_port;
#endif
remport= htons(30000);

	he= gethostbyname(servername);
	if (he == NULL)
		fatal("unknown hostname '%s'", servername);
	if (he->h_addrtype != AF_INET)
		fatal("bad address family for '%s'", servername);
	assert(he->h_length == sizeof(hostaddr));

	fd= -1;	/* lint */
	for (i= 0; he->h_addr_list[i] != NULL; i++)
	{
		memcpy(&hostaddr, he->h_addr_list[i], sizeof(hostaddr));

		fd= socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
			return fd;
		memset(&sin, '\0', sizeof(sin));
		sin.sin_family= AF_INET;
		sin.sin_addr.s_addr= hostaddr.s_addr;
		sin.sin_port= remport;
		if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
		{
			e= errno;
			close(fd);
			if (he->h_addr_list[i+1] != NULL)
			{
				/* More addresses, ignore the error */
				fprintf(stderr,
				"Warning: unable to connect to %s:%u: %s\n",
					inet_ntoa(hostaddr), ntohs(remport),
					strerror(e));
				continue;
			}
			/* Last address, fatal error */
			fatal("cannot connect to %s:%u: %s",
				inet_ntoa(hostaddr), ntohs(remport),
				strerror(e));
		}

		/* Success */
		break;
	}

	return fd;
}
#endif /* USE_GETADDRINFO */

void tcp_shutdown(int fd)
{
	fprintf(stderr, "should shutdown connection\n");
}

void do_inout(void)
{ 
	unsigned char *buf;
	u16_t len, len1, type, extra_len, o, wo;
	int r, fd;
	struct sscp_bytes bytes_msg;

	child_pid= fork();
	if (child_pid == 0)
	{
		/* CLose output, to allow the parent to signal EOF
		 * by closing its output.
		 */
		fd= open("/dev/null", O_WRONLY);
		if (fd == -1)
		{
			fatal("unable to open /dev/null: %s",
				strerror(errno));
		}
		dup2(fd, 1);
		close(fd);
		do_in();
	}
	if (child_pid == -1)
		fatal("fork failed: %s", strerror(errno));

	/* Output from the network to the application */
	buf= os_malloc("do_inout", maxmsglen);

	signal(SIGALRM, do_alarm);
	alarm(CHILD_TO);
	for (;;)
	{
		/* Get bytes */
		r= sksc_s_readall(&bytes_msg, sizeof(bytes_msg));
		if (r == 0)
			break;
		if (r < 0)
		{
			fatal("error reading bytes from server: %s",
				r < 0 ? strerror(errno) :
				"unexpected end of file");
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
			shutdown_fatal("bad length in bytes message: %u", len);
		r= sksc_s_readall(buf, extra_len);
		if (r <= 0)
		{
			fatal("error reading bytes from server: %s",
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
		"error decoding server's data message (too short)");
		}

		for (wo= 0; wo<len1; wo += r)
		{
			r= write(1, buf+o+wo, len1-wo);
			if (r <= 0)
			{
				fatal("error writing to stdout: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
		}
		assert(wo == len1);
	}

	/* Got EOF from server */
	close(1);
	got_eof_from_net= 1;
	for (;;)
	{
		if (got_eof_from_app)
			break;
		pause();
	}
	exit(0);	/* Done */
}

void set_echo(FILE *file, int on_off)
{
	int r, fd;
	struct termios attr;

	fd= fileno(file);

	r= tcgetattr(fd, &attr);
	if (r == -1)
		fatal("tcgetattr failed: %s", strerror(errno));

	if (on_off)
		attr.c_lflag |= ECHO;
	else
		attr.c_lflag &= ~ECHO;

	r= tcsetattr(fd, TCSADRAIN, &attr);
	if (r == -1)
		fatal("tcgetattr failed: %s", strerror(errno));
}

static void do_in(void)
{
	int r, t_errno;
	unsigned char *buf, *cp;
	u16_t o, len1, totlen, pad;
	struct sscp_bytes *bytes_msg;

	/* Input from the application to the network */
	buf= os_malloc("do_in", maxmsglen);
	bytes_msg= (struct sscp_bytes *)buf;
	for (;;)
	{
		o= sizeof(*bytes_msg)+2;
		r= read(0, buf+o, maxmsglen-o);
		if (r < 0)
		{
			fatal("error reading from application: %s",
				strerror(errno));
		}

		len1= r;
		assert(len1 == r);

		if (len1 == 0)
		{
			/* Send EOF */
			r= sksc_c_writeall(buf, 0);
			if (r <= 0)
			{
				t_errno= errno;
				kill_parent(SIGUSR1);
				errno= t_errno;
				fatal("error sending data to server: %s",
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

		r= sksc_c_writeall(buf, totlen);
		if (r <= 0)
		{
			t_errno= errno;
			kill_parent(SIGUSR1);
			errno= t_errno;
			fatal("error sending data to server: %s",
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
	if (pid == child_pid && !got_eof_from_app)
		fatal("child died");

	alarm(CHILD_TO);
}

static void kill_parent(int sig)
{
	pid_t ppid;

	ppid= getppid();
	if (ppid != 1)
		kill(ppid, sig);	/* Ignore errors */
}

/*
 * $PchId: os_linux.c,v 1.2 2011/12/28 11:57:54 philip Exp $
 */
