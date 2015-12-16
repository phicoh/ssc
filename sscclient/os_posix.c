/*
os_posix.c

Operating specific functions for POSIX

Created:	Nov 2008 by Philip Homburg
*/

#include "config.h"
#include "os.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <termios.h>
#include <sys/select.h>

#include "../lib/sksc/sksc.h"
#include "sscclient.h"

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
	hints.ai_socktype= SOCK_STREAM;
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

void do_inout(int tcp_fd)
{ 
	u16_t type;
	int r, loc_eof, rem_eof;
	fd_set in_set, out_set;
	size_t o, len, len1, pad, totlen,
		locout_offset, locout_size,
		remin_offset, 
		remout_offset, remout_size;
	unsigned char *cp, *locin_buf, *remout_buf;
	struct sscp_bytes *bytes_msg;

	if (!isatty(0))
		fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	if (!isatty(1))
		fcntl(1, F_SETFL, fcntl(1, F_GETFL) | O_NONBLOCK);
	fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);

	loc_eof= 0;
	rem_eof= 0;
	locout_offset= 0;
	locout_size= 0;
	locin_buf= os_malloc("do_inout", maxmsglen);
	remin_offset= 0;
	remout_buf= os_malloc("do_inout", maxmsglen);
	remout_offset= 0;
	remout_size= 0;

	assert(maxmsglen <= S_CPP_MAXMSGLEN);
	while (!loc_eof || !rem_eof)
	{
		FD_ZERO(&in_set);
		FD_ZERO(&out_set);

		/* Local to remote is easy. If there is still something in the 
		 * output buffer then try to transmit that. Otherwise read from
		 * stdin, unless we already got eof.
		 */
		if (locout_offset < locout_size)
			FD_SET(tcp_fd, &out_set);
		else if (loc_eof)
			;	/* Nothing */
		else
			FD_SET(0, &in_set);

		/* Assume one sksc message corresponds to one of our messages */
		if (remout_offset < remout_size)
			FD_SET(1, &out_set);
		else if (rem_eof)
			;	/* Nothing */
		else
			FD_SET(tcp_fd, &in_set);

		r= select(tcp_fd+1, &in_set, &out_set, NULL, NULL);
		if (r == -1)
			fatal("select failed: %s", strerror(errno));
		else if (r == 0)
			fatal("select return 0");

		if (FD_ISSET(0, &in_set))
		{
			bytes_msg= (struct sscp_bytes *)locin_buf;
			o= sizeof(*bytes_msg)+2;
			r= read(0, locin_buf+o, maxmsglen-o);
			if (r < 0)
			{
				fatal("error reading from application: %s",
					strerror(errno));
			}

			len1= r;

			if (len1 == 0)
			{
				r= sksc_encrypt(&sksc_c, locin_buf, 0,
					sksc_c_outbuf+4,
					sizeof(sksc_c_outbuf)-4);
				if (r < 0)
					fatal("sksc_encrypt failed");

				u32_to_be(r+4, sksc_c_outbuf);
				locout_offset= 0;
				locout_size= r+4;

				loc_eof= 1;

				continue;
			}

			totlen= sizeof(*bytes_msg) + 2+len1;
			if (totlen < 32)
				pad= 32-totlen;
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

			assert(cp == locin_buf+totlen);

			r= sksc_encrypt(&sksc_c, locin_buf, totlen,
				sksc_c_outbuf+4, sizeof(sksc_c_outbuf)-4);
			if (r < totlen)
				fatal("sksc_encrypt failed");
			u32_to_be(r+4, sksc_c_outbuf);
			locout_offset= 0;
			locout_size= r+4;

			/* Trigger write */
			FD_SET(tcp_fd, &out_set);
		}
		if (FD_ISSET(tcp_fd, &out_set))
		{
			assert(locout_offset < locout_size);
			r= write(tcp_fd, sksc_c_outbuf+locout_offset,
				locout_size-locout_offset);
			if (r <= 0)
			{
				if (r == -1 && errno == EAGAIN)
					continue;
				fatal("error sending data to server: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			locout_offset += r;
		}
		if (FD_ISSET(tcp_fd, &in_set))
		{
			if (remin_offset < 4)
			{
				r= read(tcp_fd, sksc_s_inbuf+remin_offset,
					4-remin_offset);
				if (r <= 0)
				{
					if (r == -1 && errno == EAGAIN)
						continue;
					fatal(
					"error reading data from server: %s",
						r < 0 ? strerror(errno) :
						"unexpected end of file");
				}
				remin_offset += r;
			}
			if (remin_offset < 4)
				continue;

			len= u32_from_be(sksc_s_inbuf);
			if (len < 4)
			{
				fatal("got bad length from server: %u", len);
			}
			if (len > sizeof(sksc_s_inbuf))
			{
				fatal("got bad length from server: %u", len);
			}

			assert(remin_offset < len);
			r= read(tcp_fd, sksc_s_inbuf+remin_offset,
				len-remin_offset);
			if (r <= 0)
			{
				if (r == -1 && errno == EAGAIN)
					continue;
				fatal(
				"error reading data from server: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			remin_offset += r;

			if (remin_offset < len)
				continue;

			remin_offset= 0;

			r= sksc_decrypt(&sksc_s, sksc_s_inbuf+4, len-4,
				remout_buf, maxmsglen);
			if (r < 0)
			{
				fprintf(stderr, 
"sksc_s_readall: sksc_decrypt failed: len = %lu, sizeof(sksc_s_buf) = %ld\n",
					(unsigned long)len-4,
					(unsigned long)sizeof(sksc_s_inbuf));
				fatal("sksc_decrypt failed");
			}
			if (r == 0)
			{
				rem_eof= 1;
				close(1);	/* Close stdout to signal EOF */
				continue;
			}

			if (r < 4)
				fatal("sksc message too small");

			bytes_msg= (struct sscp_bytes *)remout_buf;
			len= u16_from_be(bytes_msg->sb_len);
			type= u16_from_be(bytes_msg->sb_type);

			if (type != S_BYTES_TYPE)
				fatal("bad type in bytes message: %u", type);
			if (len < sizeof(*bytes_msg)+2)
			{
				fatal("bad length in bytes message: %u",
					len);
			}
			if (len != r)
			{
				fatal(
				"sksc message does not match our message");
			}

			o= sizeof(*bytes_msg);

			len1= u16_from_be(remout_buf+o);
			o += 2;

			if (o+len1 > len)
			{
				shutdown_fatal(
			"error decoding server's data message (too short)");
			}

			remout_offset= o;
			remout_size= o+len1;
			
			FD_SET(1, &out_set);
		}
		if (FD_ISSET(1, &out_set))
		{
			assert(remout_offset < remout_size);
			r= write(1, remout_buf+remout_offset,
				remout_size-remout_offset);
			if (r <= 0)
			{
				fatal("error sending data to client: %s",
					r < 0 ? strerror(errno) :
					"unexpected end of file");
			}
			remout_offset += r;
		}
	}
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

/*
 * $PchId: os_posix.c,v 1.3 2012/01/26 19:53:14 philip Exp $
 */
