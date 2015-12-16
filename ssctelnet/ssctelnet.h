/*
ssctelnet.h

Created:	Dec 2011 by Philip Homburg
*/

extern int esc_char;
extern int do_sigwinch;

/* ssctelnet.c */
int writeall (int fd, char *buffer, int buf_size);
int process_opt (char *bp, int count);
void fatal(char *fmt, ...);

/* os.c */
void do_inout(int p_in, int p_out);
void add_rem_output(char *buffer, int buf_size);

/*
 * $PchId: ssctelnet.h,v 1.1 2012/01/26 19:49:55 philip Exp $
 */
