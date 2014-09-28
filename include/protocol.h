/*
protocol.h

Simple Secure Channel Protocol parameters and definitions

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* Message 1 and message 2: server and client protocol versions */
#define SV_LABEL_LEN	4
#define SV_LABEL	"SSCP"
#define SV_VERSION_ERROR	0x00000000
#define SV_VERSION_ONE		0x00010000

struct sscp_version
{
	char sv_label[SV_LABEL_LEN];
	u8_t sv_version[4];
};

/* Message 3: client protocol parameters */
#define S_CPP_TYPE	3

/* Suggested limits and defaults */
#define S_CPP_MAXMSGLEN		(16*1024)
#define S_CPP_MAXMSGLEN_MIN	1024	/* Reasonable min. for sc_maxmsglen */
#define S_CPP_MODMIN	2048

struct sscp_cpp
{
	u8_t sc_len[2];		/* Length of message, 12 */
	u8_t sc_type[2];	/* Type of message, 3 */
	u8_t sc_maxmsglen[4];	/* Max. plaintext in SKSC message */
	u8_t sc_modmin[4];	/* Min. bits in modulus */
};

/* Message 4: server protocol parameters */
#define S_SPP_TYPE	4
#define S_SPP_MAXMSGLEN_ERROR	0	/* Client's max. is too low */
#define S_SPP_SUBGROUP_BITS	256	/* Sub-group size */

/* Suggested limits and defaults */
#define S_SPP_MAXMSGLEN		16000
#define S_SPP_MAXMSGLEN_MIN	1024	/* Reasonable min. for ss_maxmsglen */
#define S_SPP_MOD_MAX		8192	/* Max. number of bits in modulus */

struct sscp_spp
{
	u8_t ss_len[2];		/* Length of message, at least 16 */
	u8_t ss_type[2];	/* Type of message, 4 */
	u8_t ss_maxmsglen[4];	/* Max. plaintext in SKSC message */
	/* Four variable sized integers */
};

/* Message 5: client DH Public Key */
#define S_CPK_TYPE	5

struct sscp_cpk
{
	u8_t sc_len[2];		/* Length of message, at least 6 */
	u8_t sc_type[2];	/* Type of message, 5 */
	/* One variable sized integer */
};


/* Message 6: server signature */
#define S_SSIG_TYPE	6

struct sscp_ssig
{
	u8_t ss_len[2];		/* Length of message, at least 8 */
	u8_t ss_type[2];	/* Type of message, 6 */
	/* Two variable sized integers */
};

/* Message 7: client signature */
#define S_CSIG_TYPE	7

struct sscp_csig
{
	u8_t sc_len[2];		/* Length of message, at least 10 */
	u8_t sc_type[2];	/* Type of message, 7 */
	u8_t sc_flags[2];	/* Flags */
	/* Two variable sized integers */
};

#define S_CSIG_F_INVALID	1	/* Ignore signature */

/* Message 8: client remote user and service request */
#define S_CRUSR_TYPE	8

struct sscp_crusr
{
	u8_t sc_len[2];		/* Length of message, at least 8 */
	u8_t sc_type[2];	/* Type of message, 8 */
	/* Two variable length strings */
};

/* Message 9: remote user signature */
#define S_RUSIG_TYPE	9

struct sscp_rusig
{
	u8_t sr_len[2];		/* Length of message, at least 10 */
	u8_t sr_type[2];	/* Type of message, 9 */
	u8_t sr_flags[2];	/* Flags */
	/* Two variable sized integers */
};

#define S_RUSIG_F_INVALID	1	/* Ignore signature */

/* Message 10: password */
#define S_PASSWORD_TYPE	10

struct sscp_password
{
	u8_t sp_len[2];		/* Length of message, at least 8 */
	u8_t sp_type[2];	/* Type of message, 10 */
	u8_t sp_flags[2];	/* Flags */
	/* One variable length string */
};

#define S_PASSWORD_F_INVALID	1	/* Ignore password */

/* Message 11: access status */
#define S_AS_TYPE	11

struct sscp_as
{
	u8_t sa_len[2];		/* Length of message, 6 */
	u8_t sa_type[2];	/* Type of message, 11 */
	u8_t sa_flags[2];	/* Flags */
};

#define S_AS_F_DENIED	1	/* Access denied */

/* Message 257: byte stream */
#define S_BYTES_TYPE	257

struct sscp_bytes
{
	u8_t sb_len[2];		/* Length of message, at least 6 */
	u8_t sb_type[2];	/* Type of message, 257 */
	/* One variable length string */
};

#endif /* PROTOCOL_H */

/*
 * $PchId: protocol.h,v 1.1 2005/05/25 14:45:27 philip Exp $
 */
