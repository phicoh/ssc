/*
sscserver.h

General defines and declarations

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../lib/prnd/prnd.h"
#include "../lib/sha2/sha2.h"

/* auth.c */
void get_user_service(void);
void get_password(void);
int access_status(void);
char *auth_user_key_file(void);
void check_access_pk(u8_t hash[SHA256_DIGEST_LENGTH]);
void check_access_password(void);
char *get_user(void);
struct passwd *get_pwd_entry(void);

/* dh.c */
void do_dh(prnd_t *prndp, u32_t *maxmsglenp,
	SHA256_CTX *prot_ctx, SHA256_CTX *dhsec_ctx);

/* rsa.c */
void rsa_host_sign(char *keyfilename, SHA256_CTX *ctx);
int rsa_user_sig(SHA256_CTX *ctx, u8_t pk_hash[SHA256_DIGEST_LENGTH]);
void rsa_user_sign(char *keyfilename, SHA256_CTX *ctx);

/* service.c */
int check_service(char *service);
void do_service(void);

/* sscserver.c */
int readall(void *buf, size_t size);
int writeall(void *buf, size_t size);
int sksc_c_readall(void *data, size_t len);
int sksc_s_writeall(void *data, size_t len);
void u16_to_be(U16_t v, u8_t buf[2]);
void u32_to_be(u32_t v, u8_t buf[4]);
u16_t u16_from_be(u8_t buf[2]);
u32_t u32_from_be(u8_t buf[4]);
void fatal(char *fmt, ...);
void shutdown_fatal(char *fmt, ...);

/* os_<OS>.c */
void tcp_shutdown(int fd);
void prepare_id(char*user);
void do_inout(int p_in, int p_out);
void get_pty(uid_t uid, gid_t gid, int *fdp, char **tty_namep);
void do_hostname(int fd);
void login_pty(char *user, uid_t uid);
void logout_pty(void);
int pw_valid(struct passwd *pe, char *password);

/* sscserver.c */
extern u32_t maxmsglen;	/* Maximum number of plaintext bytes in a SKSC
			 * message.
			 */
extern char *sfile_name;

/*
 * $PchId: sscserver.h,v 1.1 2005/05/25 14:03:57 philip Exp $
 */
