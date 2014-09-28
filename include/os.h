/*
os.h

Operating system specific includes and defines

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#ifdef __minix

#ifdef __minix_vmd
#define _POSIX_C_SOURCE 2
#define _MINIX_SOURCE
#else
#define _MINIX
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef __minix_vmd
#include <sys/syslog.h>
#else
#define _BYTEORDER_32	0x04030201
void openlog(const char *, int, int);
#define	LOG_PID		0x01
#define	LOG_DAEMON	(3<<3)	/* system daemons */
int setlogmask(int);
#define	LOG_UPTO(pri)	((1 << ((pri)+1)) - 1)
int syslog(int level, char *fmt, ...);
int vsyslog(int level, char *fmt, va_list ap);
#define LOG_ERR		3
#define LOG_INFO	6
#define	LOG_NOTICE	5
#define	LOG_DEBUG	7	/* debug-level messages */
size_t strlcat(char *_dst, const char *_src, size_t _siz);
size_t strlcpy(char *_dst, const char *_src, size_t _siz);
#define initgroups(n,b) 0
#endif

size_t strlcat(char *_dst, const char *_src, size_t _siz);
size_t strlcpy(char *_dst, const char *_src, size_t _siz);

#endif /* __minix */

/* Provided by libos.a */
void os_random_data(void *data, size_t len);
void *os_malloc(char *label, size_t size);
void *os_realloc(char *label, void *buf, size_t size);
void os_free(void *buf);

/*
 * $PchId: os.h,v 1.2 2005/06/01 10:13:08 philip Exp $
 */
