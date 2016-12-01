/*
tcpmux.c

Implementation of the TCPMUX protocol for one service (RFC-1078)

Created:	April 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/sscversion.h"

char *progname;

static char *get_service(void);
static void fatal(char *fmt, ...);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, ind;
	char *s, *service, *path, **args;

	(progname= strrchr(argv[0],'/')) ? progname++ : (progname=argv[0]);

	while(c= getopt(argc, argv, "?V"), c != -1)
	{
		switch(c)
		{
		case '?':
			usage();
		case 'V':
			fatal("version %s", sscversion);
		default:
			fatal("getopt failed: '%c'", c);
		}
	}

	ind= 1;

	if (argc <= ind)
		usage();
	service= argv[ind++];

	if (argc <= ind)
		usage();
	path= argv[ind++];

	if (argc <= ind)
		usage();
	args= &argv[ind];

	s= get_service();
	if (strcmp(s, service) != 0)
	{
		printf("-unknown service\r\n");
		exit(1);
	}
	printf("+OK\r\n");
	fflush(stdout);

	execv(path, args);

	syslog(LOG_ERR, "unable to exec '%s': %s", path, strerror(errno));

	return 1;
}

static char *get_service(void)
{
	static char line[1024];

	int c, i;

	for (i= 0; i<sizeof(line); i++)
	{
		c= getchar();
		if (c == -1)
			return "";
		if (c == '\r')
			break;
		line[i]= c;
	}
	if (i == sizeof(line))
		return "";
	line[i]= '\0';
	c= getchar();
	if (c == '\n')
		return line;
	return "";
}

static void fatal(char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");

	exit(1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: tcpmux [-V] <service> <path> <arg0>...\n");
	exit(1);
}

/*
 * $PchId: tcpmux.c,v 1.1 2005/05/13 10:04:09 philip Exp $
 */
