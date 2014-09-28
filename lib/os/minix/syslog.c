/*
syslog.c

Created:	April 2005 by Philip Homburg for NAH6

Trivial syslog implementation for Minix
*/

#include "../../../include/os.h"

#ifndef __minix_vmd

static FILE *log= NULL;

static void open_logfile(void);

int syslog(int level, char *fmt, ...)
{
	va_list ap;

	if (log == NULL)
		open_logfile();

	va_start(ap, fmt);
	vfprintf(log, fmt, ap);
	va_end(ap);
	fprintf(log, "\n");

	fflush(log);

	return 0;
}

int vsyslog(int level, char *fmt, va_list ap)
{
	if (log == NULL)
		open_logfile();

	vfprintf(log, fmt, ap);
	fprintf(log, "\n");

	fflush(log);

	return 0;
}

void openlog(const char *ident, int logstat, int logfac)
{
	/* Nothing */
}

int setlogmask(int mask)
{
	return mask;	/* Not quite right */
}

static void open_logfile(void)
{
	int fd;

	fd= open("/dev/console", O_WRONLY | O_NOCTTY);
	if (fd == -1) fd= open("/dev/tty", O_WRONLY | O_NOCTTY);
	if (fd == -1) fd= open("/dev/null", O_WRONLY | O_NOCTTY);
	if (fd == -1) abort();

	log= fdopen(fd, "w");
	if (log == NULL) abort();
}

#endif /* !__minix_vmd */

/*
 * $PchId: syslog.c,v 1.2 2005/06/01 10:19:24 philip Exp $
 */
