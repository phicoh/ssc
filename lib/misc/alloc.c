/*
alloc.c

Memory allocation interface that aborts the program when an out of memory
condition is detected.

Created:	May 2005 by Philip Homburg for NAH6
*/

#include "../../include/os.h"

void *os_malloc(char *label, size_t size)
{
	void *buf;

	buf= malloc(size);
	if (buf != NULL)
		return buf;

	syslog(LOG_ERR,
		"out of memory, unable to allocate %u bytes, label '%s'",
		size, label);

	/* Dumping core is not a good idea. */
	exit(1);
}

void *os_realloc(char *label, void *buf, size_t size)
{
	buf= realloc(buf, size);
	if (buf != NULL)
		return buf;

	syslog(LOG_ERR,
		"out of memory, unable to (re)allocate %u bytes, label '%s'",
		size, label);

	/* Dumping core is not a good idea. */
	exit(1);
}

void os_free(void *buf)
{
	free(buf);
}

/*
 * $PchId: alloc.c,v 1.2 2005/05/25 15:21:05 philip Exp $
 */
