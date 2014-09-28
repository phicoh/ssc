/*
random.c

Fill a block with random data from the random device

Created:	April 2005 by Philip Homburg for NAH6
*/

#include "../../../include/os.h"

#define DEV_RANDOM	"/dev/random"

void os_random_data(void *data, size_t len)
{
	int fd;
	char *cp;
	ssize_t r;

	fd= open(DEV_RANDOM, O_RDONLY);
	if (fd == -1)
	{
		syslog(LOG_ERR, "unable to open random device '%s': %s",
			DEV_RANDOM, strerror(errno));
		exit(1);
	}

	for (cp= data; len > 0; cp += r, len -= r)
	{
		r= read(fd, cp, len);
		if (r <= 0)
		{
			syslog(LOG_ERR, "error reading from random device: %s",
				r == 0 ? "unexpected EOF" : strerror(errno));
			exit(1);
		}
	}
	close(fd);
}

/*
 * $PchId: random.c,v 1.1 2005/05/03 12:05:26 philip Exp $
 */
