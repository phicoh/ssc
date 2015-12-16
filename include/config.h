/*
config.h
*/

/* Local configuration? */

#if defined(ARCH_BSD) || defined(ARCH_LINUX) || defined(ARCH_OSX)

#define USE_GETADDRINFO	1

#endif

/* Set USE_GETADDRINFO is you want to use getaddrinfo instead of
 * gethostbyname
 */
#ifndef USE_GETADDRINFO
#define USE_GETADDRINFO	0
#endif

/*
 * $PchId: config.h,v 1.4 2012/01/27 15:58:25 philip Exp $
 */
