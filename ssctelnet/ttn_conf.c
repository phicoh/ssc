/*
ttn_conf.c
*/

#include "ttn.h"

int DO_echo= FALSE;
int DO_echo_allowed= TRUE;
int WILL_terminal_type= FALSE;
int WILL_terminal_type_allowed= TRUE;
int DO_suppress_go_ahead= FALSE;
int DO_suppress_go_ahead_allowed= TRUE;
int WILL_naws= FALSE;			/* negotiate about window size */
int WILL_naws_allowed= TRUE;

/*
 * $PchId: ttn_conf.c,v 1.2 2011/12/25 12:32:34 philip Exp $
 */
