/*
ssc_runas.c

Run a command as a different user

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/sscversion.h"

char *progname;

static void fatal(char *fmt, ...);
static void usage(void);

int main(int argc, char *argv[])
{
	int c, r;
	char *user, *prog, **list;
	struct passwd *pe;

	openlog("ssc_runas", LOG_CONS, LOG_AUTH);

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

	if (argc < 4)
		usage();

	user= argv[1];
	prog= argv[2];
	list= argv+3;

	pe= getpwnam(user);
	if (pe == NULL)
	{
		syslog(LOG_ERR, "getpwnam failed for user '%s'", user);
		exit(1);
	}
	r= initgroups(pe->pw_name, pe->pw_gid);
	if (r == -1)
	{
		syslog(LOG_ERR, "initgroups failed for user '%s': %s",
			user, strerror(errno));
		exit(1);
	}

	r= setuid(pe->pw_uid);
	if (r == -1)
	{
		syslog(LOG_ERR, "setuid failed for user '%s': %s",
			user, strerror(errno));
		exit(1);
	}
	r= setgid(pe->pw_gid);
	if (r == -1)
	{
		syslog(LOG_ERR, "setgid failed for user '%s': %s",
			user, strerror(errno));
		exit(1);
	}

	if (getuid() != pe->pw_uid || geteuid() != pe->pw_uid ||
		getgid() != pe->pw_gid || getegid() != pe->pw_gid)
	{
		syslog(LOG_ERR, "user or groups ID did not sick");
		exit(1);
	}

	execv(prog, list);
	syslog(LOG_ERR, "execv '%s' failed: %s", prog, strerror(errno));
	exit(1);
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
	fprintf(stderr, "Usage: %s [-V] <login> <executable> <argv0>...\n",
		progname);
	exit(1);
}

/*
 * $PchId: ssc_runas.c,v 1.2 2011/12/28 11:46:05 philip Exp $
 */
