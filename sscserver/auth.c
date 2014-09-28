/*
auth.c

Authentication information

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/protocol.h"
#include "sscserver.h"

/* Add this to $HOME */
#define PRIV_KEY_PATH	"/.ssc/key-priv"
#define CLIENT_KEY_PATH	"/.ssc/client-keys"

#define PUBKEY_HASH_TAG	"RSA3-SHA256"

static char *user, *service, *password;
static int access_granted= 0;	/* Default is no access */
static struct passwd *pwd_entry;
static char *home;

static char *read_line(FILE *file, char *filename);

void get_user_service(void)
{
	int r;
	u16_t len, len1, len2, type;
	u32_t o;
	size_t extra_len;
	u8_t *extra;
	struct sscp_crusr crusr_msg;

	/* Get the desired user and service */
	r= sksc_c_readall(&crusr_msg, sizeof(crusr_msg));
	if (r <= 0)
	{
		fatal("error reading user/service from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	len= u16_from_be(crusr_msg.sc_len);
	type= u16_from_be(crusr_msg.sc_type);

	if (type != S_CRUSR_TYPE)
	{
		shutdown_fatal("bad type in client user/service message: %u",
			type);
	}
	if (len < sizeof(crusr_msg)+2)
	{
		shutdown_fatal("bad length in client user/service message: %u",
			len);
	}

	extra_len= len-sizeof(crusr_msg);
	extra= os_malloc("get_user_service", extra_len);
	r= sksc_c_readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading user/service from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	o= 0;

	/* User name */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1+2 > extra_len)
	{
		shutdown_fatal(
		"error decoding client's user/service message (too short)");
	}
	user= os_malloc("get_user_service", len1+1);
	memcpy(user, extra+o, len1);
	user[len1]= '\0';
	o += len1;

	/* Service */
	assert(o+2 <= extra_len);
	len2= u16_from_be(extra+o);
	o += 2;
	if (o+len2 > extra_len)
	{
		shutdown_fatal(
		"error decoding client's user/service message (too short)");
	}
	service= os_malloc("get_user_service", len2+1);
	memcpy(service, extra+o, len2);
	service[len2]= '\0';
	o += len2;

	assert(o <= extra_len);
	os_free(extra);

	pwd_entry= getpwnam(user);
	if (pwd_entry != NULL)
		home= pwd_entry->pw_dir;
	else
		home= NULL;
}

void get_password(void)
{
	int r;
	u16_t len, len1, type, flags;
	u32_t o;
	size_t extra_len;
	u8_t *extra;
	struct sscp_password pw_msg;

	/* Get the password */
	r= sksc_c_readall(&pw_msg, sizeof(pw_msg));
	if (r <= 0)
	{
		fatal("error reading password from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	len= u16_from_be(pw_msg.sp_len);
	type= u16_from_be(pw_msg.sp_type);
	flags= u16_from_be(pw_msg.sp_flags);

	if (type != S_PASSWORD_TYPE)
	{
		shutdown_fatal("bad type in client password message: %u",
			type);
	}
	if (len < sizeof(pw_msg)+2)
	{
		shutdown_fatal("bad length in client password message: %u",
			len);
	}

	extra_len= len-sizeof(pw_msg);
	extra= os_malloc("get_password", extra_len);
	r= sksc_c_readall(extra, extra_len);
	if (r <= 0)
	{
		fatal("error reading password from client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}
	o= 0;

	/* Password */
	assert(o+2 <= extra_len);
	len1= u16_from_be(extra+o);
	o += 2;
	if (o+len1 > extra_len)
	{
		shutdown_fatal(
		"error decoding client's password message (too short)");
	}
	password= os_malloc("get_password", len1+1);
	memcpy(password, extra+o, len1);
	password[len1]= '\0';
	o += len1;

	assert(o <= extra_len);
	os_free(extra);

	if (flags & S_PASSWORD_F_INVALID)
	{
		os_free(password);
		password= NULL;
	}
}

int access_status(void)
{
	int r;
	struct sscp_as as_msg;

	if (check_service(service) < 0)
		access_granted= 0;

	u16_to_be(sizeof(as_msg), as_msg.sa_len);
	u16_to_be(S_AS_TYPE, as_msg.sa_type);
	u16_to_be(access_granted ? 0 : S_AS_F_DENIED, as_msg.sa_flags);

	r= sksc_s_writeall(&as_msg, sizeof(as_msg));
	if (r <= 0)
	{
		fatal("error sending access message to client: %s",
			r < 0 ? strerror(errno) : "unexpected end of file");
	}

	if (!access_granted)
	{
		shutdown_fatal("access denied for user '%s', service '%s'",
			user, service);

		/* Just in case */
		return -1;
	}
	return 0;
}

char *auth_user_key_file(void)
{ 
	size_t len;
	char *priv_key_path;

	if (home == NULL)
		return NULL;

	len= strlen(home)+sizeof(PRIV_KEY_PATH);
	priv_key_path= os_malloc("auth_user_key_file", len);
	strlcpy(priv_key_path, home, len);
	strlcat(priv_key_path, PRIV_KEY_PATH, len);
	assert(strlen(priv_key_path)+1 == len);

	return priv_key_path;
}

void check_access_pk(u8_t hash[SHA256_DIGEST_LENGTH])
{
	size_t len;
	char *client_key_path, *line, *cp, *cp1;
	int i, d0, d1, bad;
	FILE *file;

	access_granted= 0;	/* Just in case */

	/* Should check for zero hash */

	if (home == NULL)
		return;

	len= strlen(home)+sizeof(CLIENT_KEY_PATH);
	client_key_path= os_malloc("check_access_pk", len);
	strlcpy(client_key_path, home, len);
	strlcat(client_key_path, CLIENT_KEY_PATH, len);
	assert(strlen(client_key_path)+1 == len);

	file= fopen(client_key_path, "r");
	if (file == NULL)
	{
		syslog(LOG_INFO, "unable to open '%s': %s",
			client_key_path, strerror(errno));
		os_free(client_key_path);
		return;
	}

	for (;;)
	{
		line= read_line(file, client_key_path);
		if (line == NULL)
			break;

		/* Trim white space from the end */
		len= strlen(line);
		while (len > 0)
		{
			if (line[len-1] != ' ' && line[len-1] != '\t')
				break;
			len--;
			line[len]= '\0';
		}

		/* Skip leading white space */
		for (cp= line; cp[0] == ' ' || cp[0] == '\t'; cp++)
			; /* do nothing */
		if (cp[0] == '#')
		{
			/* Skip comment lines */
			os_free(line);
			continue;
		}

		/* Get size of tag */
		for (cp1= cp;
			cp1[0] != '\0' && cp1[0] != ' ' && cp1[0] != '\t';
			cp1++)
		{
			/* nothing to do */
		}
		if (cp1-cp != sizeof(PUBKEY_HASH_TAG)-1 ||
			strncmp(line, PUBKEY_HASH_TAG,
				sizeof(PUBKEY_HASH_TAG)-1) != 0)
		{
			/* Stop when we encouter a line we don't understand */
			os_free(line);
			break;
		}

		/* Skip white space */
		for (cp= cp1; cp[0] == ' ' || cp[0] == '\t'; cp++)
			;	/* nothing to do */
		if (cp == cp1)
		{
			syslog(LOG_INFO,
		"no white space after public key tag in file '%s'",
				client_key_path);
			os_free(line);
			break;
		}
		if (strlen(cp) != SHA256_DIGEST_LENGTH*2)
		{
			syslog(LOG_INFO, "bad public key length in file '%s'",
				client_key_path);
			os_free(line);
			break;
		}
		bad= 0;
		for (i= 0; i<SHA256_DIGEST_LENGTH; i++)
		{
			d0= cp[i*2];
			d1= cp[i*2+1];
			if (d0 >= '0' && d0 <= '9')
				d0 -= '0';
			else if (d0 >= 'A' && d0 <= 'F')
				d0= d0-'A' + 10;
			else if (d0 >= 'a' && d0 <= 'f')
				d0= d0-'a' + 10;
			else
				break;
			if (d1 >= '0' && d1 <= '9')
				d1 -= '0';
			else if (d1 >= 'A' && d1 <= 'F')
				d1= d1-'A' + 10;
			else if (d1 >= 'a' && d1 <= 'f')
				d1= d1-'a' + 10;
			else
				break;
			if ((d0 << 4 | d1) != hash[i])
				bad= 1;
		}
		os_free(line);
		if (i != SHA256_DIGEST_LENGTH)
		{
			syslog(LOG_INFO,
				"bad hex digit in public key in file '%s'",
					client_key_path);
			break;
		}
		if (!bad)
		{
			/* Found a matching key */
			access_granted= 1;
			break;
		}
	}
	fclose(file);
	os_free(client_key_path);
}

void check_access_password(void)
{
	if (!password)
		return;

	/* A supplied password has to be correct, override access granted to
	 * a key.
	 */
	access_granted= pw_valid(pwd_entry, password);
}

char *get_user(void)
{
	return user;
}

struct passwd *get_pwd_entry(void)
{
	return pwd_entry;
}

static char *read_line(FILE *file, char *filename)
{
	char *line;
	size_t offset, size, len;

	size= 80;
	offset= 0;
	line= os_malloc("read_line", size);
	for (;;)
	{
		if (offset+1 >= size)
		{
			size *= 2;
			line= os_realloc("read_line", line, size);
		}
		assert(offset+1 < size);
		if (fgets(line+offset, size-offset, file) == NULL)
		{
			if (feof(file))
			{
				if (offset == 0)
				{
					os_free(line);
					return NULL;
				}
				syslog(LOG_INFO,
					"unexpected end of key file '%s'",
					filename);
			}
			else
			{
				syslog(LOG_ERR,
					"error reading key file '%s': %s",
					filename, strerror(errno));
			}
			os_free(line);
			return NULL;
		}
		len= strlen(line+offset);
		if (len == 0)
		{
			syslog(LOG_ERR, "unexpected end of key file '%s'",
				filename);
			os_free(line);
			return NULL;
		}
		offset += len;
		if (line[offset-1] == '\n')
			break;
	}
	line[offset-1]= '\0';
	return line;
}


/*
 * $PchId: auth.c,v 1.2 2005/06/01 10:24:40 philip Exp $
 */
