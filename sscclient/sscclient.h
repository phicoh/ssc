/*
sscclient.h

General defines and declarations

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../lib/sha2/sha2.h"
#include "../lib/prnd/prnd.h"
#include "../include/protocol.h"

/* Connect indirectly through the TCPMUX protocol (RFC-1078) on TCP port 1 */
#define USE_TCPMUX	1
#define SSC_PROTO_NAME	"sscp"

/* dh.c */
void do_dh(struct sscp_version *version_msgp, prnd_t *prndp, 
	u32_t *maxmsglenp,
	SHA256_CTX *prot_ctx, SHA256_CTX *dhsec_ctx);

/* rsa.c */
int rsa_server_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH]);
void rsa_user_sign(char *keyfilename, SHA256_CTX *ctx);
int rsa_remuser_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH],
	int *nosigp);

/* sscclient.c */
int readall(void *buf, size_t size);
int writeall(void *buf, size_t size);
int sksc_s_readall(void *buf, size_t size);
int sksc_c_writeall(void *buf, size_t size);
char *read_line(FILE *file);
void u16_to_be(U16_t v, u8_t buf[2]);
void u32_to_be(u32_t v, u8_t buf[4]);
u16_t u16_from_be(u8_t buf[2]);
u32_t u32_from_be(u8_t buf[4]);
void fatal(char *fmt, ...);
void shutdown_fatal(char *fmt, ...);

/* os_<OS>.c */
int tcp_connect(char *servername);
void tcp_shutdown(int fd);
void do_inout(void);
void set_echo(FILE *file, int on_off);

/* sscclient.c */
extern u32_t maxmsglen;
extern int got_eof_from_app;
extern int got_eof_from_net;

/*
 * $PchId: sscclient.h,v 1.1 2005/05/24 11:54:46 philip Exp $
 */
