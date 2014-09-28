/*
prot_rsh.h

Parameters and definitions for the Remote Shell Protocol on top of SSC

Created:	March 2005 by Philip Homburg for NAH6
*/

#define RSH_STDIN_TYPE	0	/* Message 0: stdin */
#define RSH_STDOUT_TYPE	1	/* Message 1: stdout */
#define RSH_STDERR_TYPE	2	/* Message 2: stderr */

struct sscrsh_data
{
	u8_t srd_len[2];	/* Length of message, at least 4 */
	u8_t srd_type[2];	/* Type of message, 0, 1, or 2 */
};

/* Message 0x8000: shell command */
#define RSH_CMD_TYPE	0x8000

struct sscrsh_cmd
{
	u8_t src_len[2];	/* Length of message, at least 4 */
	u8_t src_type[2];	/* Type of message, 0x8000 */
};


/*
 * $PchId: prot_rsh.h,v 1.1 2005/05/25 14:44:50 philip Exp $
 */
