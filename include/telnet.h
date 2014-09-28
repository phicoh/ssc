/*
net/gen/telnet.h

Telnet protocol

Created:	April 2001 by Philip Homburg <philip@f-mnx.phicoh.com>
*/

#ifndef NET__GEN__TELNET_H
#define NET__GEN__TELNET_H

#define TC_IAC	255		/* Start of telnet command */
#define TC_DONT	254		/* Request not to perform option */
#define TC_DO	253		/* Request to perform option */
#define TC_WONT	252		/* Peer intends not to perform option */
#define TC_WILL	251		/* Peer intends to perform option */
#define TC_SB	250		/* start of subnegotiation */
#define TC_GA	249		/* go ahead */
#define TC_EL	248		/* erase line */
#define TC_EC	247		/* erase character */
#define TC_AYT	246		/* are you there */
#define TC_AO	245		/* abort output */
#define TC_IP	244		/* send interrupt */
#define TC_BRK	243		/* send break */
#define TC_DM	242		/* data mark */
#define TC_NOP	241		/* no operation */
#define TC_SE	240		/* end of subnegotiation */

#define TELOPT_ECHO		 1	/* Remote echo */
#define TELOPT_SUP_GO_AHEAD	 3	/* suppress go ahead */
#define TELOPT_TERMINAL_TYPE	24	/* terminal type (TERM variable) */
#define		TO_TT_SB_IS	0	/* Report of terminal type */
#define		TO_TT_SB_SEND	1	/* Request to send terminal type */
#define TELOPT_NAWS		31	/* window size */
#define TELOPT_TERMINAL_SPEED	32	/* terminal speed */
#define		TO_TS_SB_IS	0	/* Report of terminal speed */
#define		TO_TS_SB_SEND	1	/* Request to send terminal speed */
#define TELOPT_XDISPLOC		35	/* X display location */
#define		TO_XDL_SB_IS	0	/* Report of display location */
#define		TO_XDL_SB_SEND	1	/* Request to send display location */

#endif /* NET__GEN__TELNET_H */

/*
 * $PchId: telnet.h,v 1.1 2005/05/25 14:46:22 philip Exp $
 */
