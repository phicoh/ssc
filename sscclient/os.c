/*
os.c

Created:	Nov 2008 by Philip Homburg
*/

#ifdef ARCH_MINIX

#include "os_minix.c"

#endif /* ARCH_MINIX */

#ifdef ARCH_LINUX

#include "os_posix.c"

#endif /* ARCH_LINUX */

#ifdef ARCH_SOLARIS

#include "os_linux.c"

#endif /* ARCH_SOLARIS */

#ifdef ARCH_BSD

#include "os_posix.c"

#endif /* ARCH_BSD */

#ifdef ARCH_OSX

#include "os_posix.c"

#endif /* ARCH_OSX */


/*
 * $PchId: os.c,v 1.3 2012/01/27 16:00:28 philip Exp $
 */
