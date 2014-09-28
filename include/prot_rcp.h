/*
prot_rcp.h

Parameters and definitions for the Remote Copy Protocol on top of SSC

Created:	March 2005 by Philip Homburg for NAH6
*/

#define SSCRCP_GET		0x001
#define SSCRCP_PUT		0x002
#define SSCRCP_GETMODE		0x003
#define SSCRCP_GETTIMES		0x004
#define SSCRCP_SETMODE		0x005
#define SSCRCP_SETTIMES		0x006
#define SSCRCP_LISTDIR		0x007
#define SSCRCP_QUIT		0x080

#define SSCRCP_COK		0x101
#define SSCRCP_CERROR		0x102
#define SSCRCP_CDATA		0x103
#define SSCRCP_CCANCEL		0x104

#define SSCRCP_SOK		0x201
#define SSCRCP_SERROR		0x202
#define SSCRCP_SDATA		0x203
#define SSCRCP_SCANCEL		0x204
#define SSCRCP_MODE_REPL	0x205
#define SSCRCP_TIMES_REPL	0x206
#define SSCRCP_DIRENTRY		0x207

struct sscrcp_hdr
{
	u8_t srh_len[2];	/* Length of message, at least 4 */
	u8_t srh_type[2];	/* Type of message */
};

struct sscrcp_setmode
{
	u8_t srsm_len[2];	/* Length of message, at least 6 */
	u8_t srsm_type[2];	/* Type of message */
	u8_t srsm_mode[2];	/* Mode of file */
	/* filename */
};

struct sscrcp_settimes
{
	u8_t srst_len[2];	/* Length of message, at least 28 */
	u8_t srst_type[2];	/* Type of message */
	u8_t srst_atime_high[4]; /* Top 32 bits of atime */
	u8_t srst_atime_low[4];  /* Middle 32 bits of atime */
	u8_t srst_atime_frac[4]; /* Low 32 bits of atime */
	u8_t srst_mtime_high[4]; /* Top 32 bits of atime */
	u8_t srst_mtime_low[4];  /* Middle 32 bits of atime */
	u8_t srst_mtime_frac[4]; /* Low 32 bits of atime */
	/* filename */
};

/* A time value is stored as a twos complement 96-bit fixed point integer
 * with a 32-bit fraction. The 96-bit value is split into 3 32-bit parts:
 * 'high', 'low', and 'frac'. Time is counted as in POSIX.
 */

struct sscrcp_mode_repl
{
	u8_t srmr_len[2];	/* Length of message, 6 */
	u8_t srmr_type[2];	/* Type of message */
	u8_t srmr_mode[2];	/* Mode of file */
};

struct sscrcp_times_repl
{
	u8_t srtr_len[2];	/* Length of message, 28 */
	u8_t srtr_type[2];	/* Type of message */
	u8_t srtr_atime_high[4]; /* Top 32 bits of atime */
	u8_t srtr_atime_low[4];  /* Middle 32 bits of atime */
	u8_t srtr_atime_frac[4]; /* Low 32 bits of atime */
	u8_t srtr_mtime_high[4]; /* Top 32 bits of atime */
	u8_t srtr_mtime_low[4];  /* Middle 32 bits of atime */
	u8_t srtr_mtime_frac[4]; /* Low 32 bits of atime */
};


/*
 * $PchId: prot_rcp.h,v 1.1 2005/05/25 14:44:26 philip Exp $
 */
