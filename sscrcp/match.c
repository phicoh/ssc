/* 
match.c

Pattern matching for shell wildcards. 

Taken from the Minix find written by Erik Baalbergen.

Extracted April 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "sscrcp.h"

/*################### SMATCH #########################*/
/* Don't try to understand the following one... */
int smatch(s, t)		/* shell-like matching */
char *s, *t;
{
  register n;

  if (*t == '\0') return *s == '\0';
  if (*t == '*') {
	++t;
	do
		if (smatch(s, t)) return 1;
	while (*s++ != '\0');
	return 0;
  }
  if (*s == '\0') return 0;
  if (*t == '\\') return (*s == *++t) ? smatch(++s, ++t) : 0;
  if (*t == '?') return smatch(++s, ++t);
  if (*t == '[') {
	while (*++t != ']') {
		if (*t == '\\') ++t;
		if (*(t + 1) != '-')
			if (*t == *s) {
				while (*++t != ']')
					if (*t == '\\') ++t;
				return smatch(++s, ++t);
			} else
				continue;
		if (*(t + 2) == ']') return(*s == *t || *s == '-');
		n = (*(t + 2) == '\\') ? 3 : 2;
		if (*s >= *t && *s <= *(t + n)) {
			while (*++t != ']')
				if (*t == '\\') ++t;
			return smatch(++s, ++t);
		}
		t += n;
	}
	return 0;
  }
  return(*s == *t) ? smatch(++s, ++t) : 0;
}


/*
 * $PchId: match.c,v 1.1 2005/05/13 12:44:56 philip Exp $
 */
