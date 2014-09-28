/*
tcpmux.c

Implementation of the TCPMUX protocol for one service (RFC-1078)

Created:	April 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"

static char *get_service(void);
static void usage(void);

int main(int argc, char *argv[])
{
	int ind;
	char *s, *service, *path, **args;

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

static void usage(void)
{
	fprintf(stderr, "Usage: tcpmux <service> <path> <arg0>...\n");
	exit(1);
}

/*
 * $PchId: tcpmux.c,v 1.1 2005/05/13 10:04:09 philip Exp $
 */
