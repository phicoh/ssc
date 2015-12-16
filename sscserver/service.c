/*
service.c

Handle a service

Created:	Feb 2005 by Philip Homburg for NAH6
*/

#include "../include/os.h"
#include "../include/protocol.h"

#include "sscserver.h"

#define SSC_RUNAS	"/usr/local/bin/ssc_runas"
#if 0	/* For Android. Should come from os.h */
#undef SSC_RUNAS
#define SSC_RUNAS	"/data/p/ssc_runas"
#endif

#define MAX_ARGS	20
#define S_ARGS		10

static struct service
{
	char *service;
	int alloc_pty;
	char *path;
	char *args[S_ARGS];
} service_info; 

static char *get_line(FILE *file);
static void get_pipe(int fds[2]);
static void start_service(int stdin_fds[2], int stdout_fds[2], int pty_fd,
	char *tty_name);
static char *dupstr(char *str);
static char *concat2(char *s1, char *s2);

int check_service(char *service)
{
	int i;
	char *line, *line1, *cp, *cp1;
	FILE *sfile;

	sfile= fopen(sfile_name, "r");
	if (sfile == NULL)
	{
		fatal("unable to open services file '%s': %s",
			sfile_name, strerror(errno));
	}

	cp= cp1= NULL;	/* lint */
	for (;;)
	{
		line= get_line(sfile);
		if (line == NULL)
			break;

		line1= dupstr(line);
		cp= line1;

		/* Skip leading white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		/* Skip comment lines */
		if (*cp == '#')
			continue;

		/* Get service field */
		cp1= cp;
		while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			cp++;
		if (*cp == '\0')
		{
			fatal("incomplete line in services file: '%s'",
				line);
		}
		*cp= '\0';
		cp++;
		
		if (strcmp(cp1, service) == 0)
			break;

		os_free(line1);
	}

	fclose(sfile);
	if (line == NULL)
		return -1;

	service_info.service= cp1;

	/* Skip leading white space */
	while (*cp == ' ' || *cp == '\t')
		cp++;

	/* Get pty field */
	cp1= cp;
	while (*cp != '\0' && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp == '\0')
	{
		fatal("incomplete line in services file: '%s'",
			line);
	}
	*cp= '\0';
	cp++;

	if (strcmp(cp1, "-") == 0)
		service_info.alloc_pty= 0;
	else if (strcmp(cp1, "pty") == 0)
		service_info.alloc_pty= 1;
	else
	{
		fatal("bad value in pty field '%s' for service '%s'",
			cp1, service);
	}

	/* Skip leading white space */
	while (*cp == ' ' || *cp == '\t')
		cp++;

	/* Get path field */
	cp1= cp;
	while (*cp != '\0' && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp == '\0')
	{
		fatal("incomplete line in services file: '%s'",
			line);
	}
	*cp= '\0';
	cp++;

	service_info.path= cp1;

	/* Skip leading white space */
	while (*cp == ' ' || *cp == '\t')
		cp++;

	/* Get argv[0] field */
	cp1= cp;
	while (*cp != '\0' && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp != '\0')
	{
		*cp= '\0';
		cp++;
	}

	service_info.args[0]= cp1;

	for (i= 1; i<S_ARGS; i++)
	{
		/* Skip leading white space */
		while (*cp == ' ' || *cp == '\t')
			cp++;

		/* Get argv[i] field */
		cp1= cp;
		while (*cp != '\0' && *cp != ' ' && *cp != '\t')
			cp++;
		if (cp == cp1)
		{
			service_info.args[i]= NULL;
			break;
		}
		if (*cp != '\0')
		{
			*cp= '\0';
			cp++;
		}
		service_info.args[i]= cp1;
	}

	if (i >= S_ARGS)
		fatal("too many argument: (> %d)", S_ARGS);

	return 0;
}

void do_service(void)
{
	int p_stdin[2], p_stdout[2];
	int p_in, p_out, pty_fd;
	int alloc_pty;
	pid_t pid;
	char *tty_name;
	struct passwd *pe;

	alloc_pty= service_info.alloc_pty;
	if (alloc_pty)
	{
		pe= get_pwd_entry();
		get_pty(pe->pw_uid, pe->pw_gid, &pty_fd, &tty_name);
	}
	else
	{
		pty_fd= -1;
		tty_name= NULL;
	}

	get_pipe(p_stdin);
	get_pipe(p_stdout);

	pid= fork();
	if (pid == 0)
		start_service(p_stdin, p_stdout, pty_fd, tty_name);
	if (pid == -1)
		fatal("fork failed: %s", strerror(errno));

	/* Close read side of stdin pipe */
	close(p_stdin[0]);
	p_out= p_stdin[1];

	/* Close write side of stdout pipe */
	close(p_stdout[1]);
	p_in= p_stdout[0];

	do_inout(p_in, p_out);

	if (alloc_pty)
		logout_pty();

	exit(0);
}

static char *get_line(FILE *file)
{
	static char *line= NULL;
	static size_t line_size;

	char *cp, *cp1;
	size_t n, o;

	if (line == NULL)
	{
		line_size= 80;
		line= os_malloc("get_line", line_size);
	}

	o= 0;
	for (;;)
	{
		if (o == line_size-1)
		{
			line_size *= 2;
			line= os_realloc("get_line", line, line_size);
		}
		assert(o < line_size);
		n= line_size-1;
		assert(n > 1);

		cp= fgets(line+o, n, file);
		if (cp == NULL)
		{
			if (feof(file))
				return NULL;
			fatal("error reading services file: %s",
				strerror(errno));
		}
		cp1= strchr(cp, '\n');
		if (cp1 != NULL)
		{
			*cp1= '\0';
			break;
		}
		o += strlen(cp);
		assert(o < line_size);
	}

	return line;
}

static void get_pipe(int fds[2])
{
	int r;

	r= pipe(fds);
	if (r == -1)
		fatal("pipe call failed: %s", strerror(errno));
}

static void start_service(int stdin_fds[2], int stdout_fds[2], int pty_fd,
	char *tty_name)
{
	int i, j;
	char *list[MAX_ARGS];
	char fd_str[10];
	char *user, *path, *env[5];
	struct passwd *pe;

	do_hostname(0);		/* fd 0 should be the TCP connection */

	dup2(stdin_fds[0], 0);
	close(stdin_fds[0]);
	close(stdin_fds[1]);

	dup2(stdout_fds[1], 1);
	dup2(stdout_fds[1], 2);
	close(stdout_fds[0]);
	close(stdout_fds[1]);

	user= get_user();
	pe= get_pwd_entry();

	/* Setup environment, copy PATH, create USER, HOME, and SHELL */
	path= getenv("PATH");
	if (path == NULL)
		path= "/bin:/usr/bin:/usr/local/bin";
	env[0]= concat2("PATH=", path);
	env[1]= concat2("USER=", user);
#if 1
	env[2]= concat2("HOME=", pe->pw_dir);
	env[3]= concat2("SHELL=", pe->pw_shell);
#else	/* For Android, should be configured in os.h */
	env[2]= concat2("HOME=", "/data/p");
	env[3]= concat2("SHELL=", "/bin/sh");
#endif
	env[4]= 0;

	list[0]= SSC_RUNAS;
	list[1]= user;
	list[2]= service_info.path;
	for (i= 3, j= 0; i<MAX_ARGS && service_info.args[j] != NULL; i++, j++)
		list[i]= service_info.args[j];
	if (tty_name != NULL)
	{
		login_pty(user, pe->pw_uid);
		assert(i<MAX_ARGS-2);
		snprintf(fd_str, sizeof(fd_str), "%u", pty_fd);
		list[i++]= fd_str;
		list[i++]= tty_name;
	}
	assert(i<MAX_ARGS);
	list[i]= NULL;

	/* Any OS specific initializations */
	prepare_id(user);

	/* Let another program drop privileges. That way, our memory is
	 * gone before a change in privileges.
	 */
	execve(SSC_RUNAS, list, env);
	fatal("execve '%s' failed: %s", SSC_RUNAS, strerror(errno));
}

static void start_service_pty(void)
{
	fatal("start_service_pty: not implemented");
}

static char *dupstr(char *str)
{
	size_t len;
	char *cp;

	len= strlen(str)+1;
	cp= os_malloc("dupstr", len);
	strlcpy(cp, str, len);
	assert(strlen(cp) == len-1);
	return cp;
}

static char *concat2(char *s1, char *s2)
{
	size_t len;
	char *cp;

	len= strlen(s1)+strlen(s2)+1;
	cp= os_malloc("concat2", len);
	strlcpy(cp, s1, len);
	strlcat(cp, s2, len);
	assert(strlen(cp) == len-1);
	return cp;
}

/*
 * $PchId: service.c,v 1.3 2011/12/28 11:54:12 philip Exp $
 */
