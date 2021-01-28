/* $Id: ftplib.c,v 1.16 2004/04/21 22:35:12 te Exp $ */

/***************************************************************************/
/*									   */
/* ftplib.c - callable ftp access routines				   */
/* Copyright (C) 1996, 1997, 1998 Thomas Pfau, pfau@cnj.digex.net	   */
/*	73 Catherine Street, South Bound Brook, NJ, 08880		   */
/*									   */
/* This library is free software; you can redistribute it and/or	   */
/* modify it under the terms of the GNU Library General Public		   */
/* License as published by the Free Software Foundation; either		   */
/* version 2 of the License, or (at your option) any later version.	   */
/* 									   */
/* This library is distributed in the hope that it will be useful,	   */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of	   */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU	   */
/* Library General Public License for more details.			   */
/* 									   */
/* You should have received a copy of the GNU Library General Public	   */
/* License along with this progam; if not, write to the			   */
/* Free Software Foundation, Inc., 59 Temple Place - Suite 330,		   */
/* Boston, MA 02111-1307, USA.						   */
/* 									   */
/***************************************************************************/

/*
 * ftplib.c v4.3, Sept. 2002, 2003, 2004.
 * Tamer Embaby <tsemba@menanet.net>
 */

/*
 * TODO/ChangeLog:
 *
 * - Proxy in net_buf with API. ftplib_connect/ftplib_login. (OK)
 * - Major change in API/struct names. (OK)
 * - All distributions in one source tree. (OK)
 * - Drop VMS. (OK)
 * - indent. (OK)
 * - RTFM. (Always)
 * - Skip ftp:// if exist in connect. (OK)
 * - debug levels: (OK)
 *	0 mandatory, will be debugged.
 *	1 debug basics plus FTP server responses.
 *	2 debug even commands sent to server.
 *	3 insane debugging
 * - User call back for debugging. (OK)
 * - Use user callback for debugging to eliminate perror() calls. (OK)
 * - Restart (resuming). (OK)
 * - Rewrite parsing output of LIST command. (OK)
 * - ABOR. (Must support threading? or caller app support it) (OK)
 * - HELP. (OK)
 * - Library version routine. (OK)
 * - File ossets to be off_t. (Status of seeko/ftello, limits on Windows?)
 *   _BSD_OFF_T (long long, fmt %lld)
 * - Number of bytes transfered routine. (OK)
 * - APPE (append). (OK)
 * - Send command directly (NOOP etc.)
 * - portreq (hi,low,incr)
 * - Second digits status code.
 * - Support EPSV/EPRT commands.
 * - Embedded quotes:
 *       MKD foo"bar
 *       257 "/usr/dm/foo""bar" directory created
 *       CWD /usr/dm/foo"bar
 *       200 directory changed to /usr/dm/foo"bar
 * - Fixed byte transfer count, it was not working. (OK)
 * - Separated callbacks, it was messy. (OK)
 * - 1/2003: Fixed error in ftplib_close while closing data connection
 *   with errornous status from FTP server, ftplib_close was trying to
 *   read 2XX from server while the server won't send anything.
 * - 4/2004: Compiled under Solaris.
 */

#if defined (__unix__)
# include <unistd.h>
#endif

#if defined (_WIN32)
# include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined (__unix__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netdb.h>
# include <arpa/inet.h>
# define SOCKET_CALL_ERR	(-1)
# define NET_ERR		(-1)
#elif defined (_WIN32)
# include <winsock.h>
# define SOCKET_CALL_ERR	INVALID_SOCKET
# define NET_ERR		SOCKET_ERROR
#endif

#define BUILDING_LIBRARY
#include "ftplib.h"

#if defined (_WIN32)
# define SETSOCKOPT_OPTVAL_TYPE (const char *)
#else
# define SETSOCKOPT_OPTVAL_TYPE (void *)
#endif

#if defined (_WIN32)
# define snprintf	_snprintf
#endif

#define FTPLIB_BUFSIZ	8192
#define ACCEPT_TIMEOUT	30

#define FTPLIB_CONTROL	0
#define FTPLIB_READ	1
#define FTPLIB_WRITE	2

/*
 * Default mode is passive.
 */
#if !defined (FTPLIB_DEFMODE)
# define FTPLIB_DEFMODE FTPLIB_PASSIVE
#endif

struct _netbuf {
	char	*cput, *cget;	/* Pointer used in reading FTP responses. */
	int	cavail, cleft;	/* Counters used in reading FTP responses. */
	int	handle;		/* Socket desctiptor */
	char	*buf;
	int	dir;		/* FTP direction, CONTROL, DATA: read/write */
	netbuf	*ctrl;		/* Control connection */
	int	cmode;		/* Passive/Port mode */
	/* 
	 * Commands to issue after PORT/PASV & before service 
	 * command (e.g., RETR/STOR) .
	 */
	int	pxfer;
#define FTP_REST	1	/* Restart, offset taken from restoff */
	struct	timeval idletime;
	int	xfered;		/* Bytes xfered in both direction counter */
	char	response[256];	/* Last response to command */
	char	*rhost;		/* Remote host */
	char	*proxy;		/* Proxy server */
	int	pmeth;		/* Proxy connect method */
#define PROXY_USER_AT_HOST	1
	size_t	restoff;	/* Offset to restart downloading from */
	/* User callbacks. */
	ftp_idle_callback idlecb;/* Callback when socket is idle */
	void	*idlearg;	/* Passed to idle callback */
	ftp_xfer_callback xfercb;/* Called when cbbytes bytes transfered */
	void	*xferarg;	/* Passed to xfercb */
	int	cbbytes;	/* NUmber of bytes reached to call xfercb */
	int	xfered1;	/* Internal counter for cbbytes */
	ftp_debug_callback udebug;
};

#define NBFREE(nbp) do { \
	if ((nbp)->buf != NULL) \
		free((nbp)->buf); \
	if ((nbp)->rhost != NULL) \
		free((nbp)->rhost); \
	if ((nbp)->proxy != NULL) \
		free((nbp)->proxy); \
	free(nbp); \
} while (0)

/* Version */
#define VERSION		"4.4"

char *version =
"ftplib Release 3.1 6/xx/98, copyright 1996, 1997, 1998 Thomas Pfau\n"
"ftplib v" VERSION ", (C) 2002, 2003, 2004 Tamer Embaby <tsemba@menanet.net>\n"
"$Id: ftplib.c,v 1.16 2004/04/21 22:35:12 te Exp $";

DEFINE int ftplib_debug = 0;

#if defined (__unix__)
# define net_read		read
# define net_write		write
# define net_close		close
#elif defined (_WIN32)
# define net_read(x,y,z)	recv(x,y,z,0)
# define net_write(x,y,z)	send(x,y,z,0)
# define net_close		closesocket
#endif

static	int socket_wait(netbuf *);
static	int readline(char *,int,netbuf *);
static	int writeline(char *,int,netbuf *);
static	int readresp(char,netbuf *);
static	int ftp_send_cmd(const char *,char,netbuf *);
static	int ftp_open_port(netbuf *,netbuf **,int,int);
static	int ftp_accept_connection(netbuf *,netbuf *);
static	int ftp_xfer(const char *,const char *,netbuf *,int,int);
static	void udebug(netbuf *,int,const char *,...);

struct	ftp_list_entry *unix_listing_parse(char *);
void	derror(const char *);

static	ftp_debug_callback dflt_debug;

/*
 * ftplib_init for stupid operating systems that require it (Windows NT)
 */
DEFINE void
ftplib_init(void)
{
#if defined (_WIN32)
	WORD wVersionRequested;
	WSADATA wsadata;
	int err;

	wVersionRequested = MAKEWORD(1, 1);
	if ((err = WSAStartup(wVersionRequested, &wsadata)) != 0)
		udebug(NULL, 0, "Network failed to start: %d\n", err);
#endif
	return;
}

DEFINE void
ftplib_deinit(void)
{

#if defined (_WIN32)
	WSACleanup();
	return;
#endif
}

/*
 * ftplib_last_response - return a pointer to the last response received
 */
DEFINE char *
ftplib_last_response(netbuf *nbp)
{

	if ((nbp != NULL) && (nbp->dir == FTPLIB_CONTROL))
		return (nbp->response);
	return (NULL);
}

/*
 * ftplib_connect - connect to remote server
 *
 * TODO: pass proxy as parameter. (OK)
 * TODO: network API return value should be check against macro. (OK)
 * TODO: free strdup()d strings. (OK)
 * TODO: FREE() for netbuf. (OK)
 *
 * return 1 if connected, 0 if not
 */
DEFINE int
ftplib_connect(const char *host, const char *proxy, netbuf **nbp)
{
	int sfd;
	struct sockaddr_in sin;
	struct hostent *phe;
	struct servent *pse;
	int on = 1;
	netbuf *ctrl;
	char *lhost, *phost;
	char *pnum;

	ctrl = calloc(1, sizeof(netbuf));
	if (ctrl == NULL) {
		derror("calloc");
		return (0);
	}
	phost = (char *)host;
	if (proxy != NULL) {
		phost = (char *)proxy;
		if ((ctrl->proxy = strdup(proxy)) == NULL) {
			udebug(NULL, 0,
			    "ftplib_connect:1: not enough memory\n");
			return (0);
		}
		ctrl->pmeth = PROXY_USER_AT_HOST;
	}
	if ((ctrl->rhost = strdup(host)) == NULL) {
		udebug(NULL, 0, "ftplib_connect:2: not enough memory\n");
		return (0);
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	if (strncmp(phost, "ftp://", 6) == 0)
		phost += 6;
	if ((lhost = strdup(phost)) == NULL) {
		udebug(NULL, 0, "ftplib_connect:3: not enough memory\n");
		NBFREE(ctrl);
		return (0);
	}
	pnum = strchr(lhost, ':');
	if (pnum == NULL) {
		if ((pse = getservbyname("ftp", "tcp")) == NULL) {
			derror("getservbyname");
			free(lhost);
			NBFREE(ctrl);
			return (0);
		}
		sin.sin_port = pse->s_port;
	} else {
		*pnum++ = '\0';
		if (isdigit(*pnum))
			sin.sin_port = htons(atoi(pnum));
		else {
			pse = getservbyname(pnum, "tcp");
			sin.sin_port = pse->s_port;
		}
	}
	udebug(NULL, 3, "::: connecting to %s port %hu\n",
	    lhost, ntohs(sin.sin_port));
	/* TODO: resolv here */
	if ((sin.sin_addr.s_addr = inet_addr(lhost)) == -1) {
		if ((phe = gethostbyname(lhost)) == NULL) {
			derror("gethostbyname");
			free(lhost);
			NBFREE(ctrl);
			return (0);
		}
		memcpy((char *) &sin.sin_addr, phe->h_addr, phe->h_length);
	}
	free(lhost);
	sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sfd == SOCKET_CALL_ERR) {
		derror("socket");
		NBFREE(ctrl);
		return (0);
	}
	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
		SETSOCKOPT_OPTVAL_TYPE &on, sizeof(on)) == NET_ERR) {
		derror("setsockopt");
		net_close(sfd);
		NBFREE(ctrl);
		return (0);
	}
	if (connect(sfd, (struct sockaddr *) &sin, sizeof(sin)) == NET_ERR) {
		derror("connect");
		net_close(sfd);
		NBFREE(ctrl);
		return (0);
	}
	udebug(NULL, 3, "::: connected!\n");
	ctrl->buf = malloc(FTPLIB_BUFSIZ);
	if (ctrl->buf == NULL) {
		derror("calloc");
		net_close(sfd);
		NBFREE(ctrl);
		return (0);
	}
	ctrl->handle	= sfd;
	ctrl->dir	= FTPLIB_CONTROL;
	ctrl->cmode	= FTPLIB_DEFMODE;
	ctrl->ctrl	= NULL;
	ctrl->idlecb	= NULL;
	ctrl->xfercb	= NULL;
	ctrl->idletime.tv_sec = ctrl->idletime.tv_usec = 0;
	ctrl->idlearg	= NULL;
	ctrl->xfered	= 0;
	ctrl->xfered1	= 0;
	ctrl->cbbytes	= 0;
	/*
	 * Read the FTP welcome message.
	 */
	if (readresp('2', ctrl) == 0) {
		net_close(sfd);
		NBFREE(ctrl);
		return (0);
	}
	*nbp = ctrl;
	return (1);
}

/*
 * ftplib_options - change connection options
 *
 * returns 1 if successful, 0 on error
 */
DEFINE int
ftplib_options(int opt, long val, netbuf *nbp)
{
	int v, rv = 0;

	switch (opt) {
	case FTPLIB_CONNMODE:
		v = (int)val;
		if ((v == FTPLIB_PASSIVE) || (v == FTPLIB_PORT)) {
			nbp->cmode = v;
			rv = 1;
		}
		break;
	case FTPLIB_IDLETIME:
		v = (int)val;
		rv = 1;
		nbp->idletime.tv_sec = v / 1000;
		nbp->idletime.tv_usec = (v % 1000) * 1000;
		break;
	case FTPLIB_IDLECALLBACK:
		nbp->idlecb = (ftp_idle_callback)val;
		rv = 1;
		break;
	case FTPLIB_IDLECALLBACKARG:
		rv = 1;
		nbp->idlearg = (void *)val;
		break;
	case FTPLIB_XFERCALLBACK:
		rv = 1;
		nbp->xfercb = (ftp_xfer_callback)val;
		break;
	case FTPLIB_XFERCALLBACKARG:
		rv = 1;
		nbp->xferarg = (void *)val;
	case FTPLIB_CALLBACKBYTES:
		rv = 1;
		nbp->cbbytes = (int)val;
		break;
	}
	return (rv);
}

/*
 * ftplib_login - log in to remote server
 *
 * TODO: Proxy login here. (OK)
 *
 * return 1 if logged in, 0 otherwise
 */
DEFINE int
ftplib_login(const char *user, const char *pass, netbuf *nbp)
{
	char tempbuf[BUFSIZ];

	if (nbp->proxy != NULL) {
		udebug(nbp, 2, "connected through proxy FTP %s\n", nbp->proxy);
		switch (nbp->pmeth) {
		case PROXY_USER_AT_HOST:
			snprintf(tempbuf, sizeof(tempbuf),
			    "USER %s@%s", user, nbp->rhost);
			break;
		default:
			return (0);	/* XXX */
		}
	} else {
		snprintf(tempbuf, sizeof(tempbuf), "USER %s", user);
	}
	if (ftp_send_cmd(tempbuf, '3', nbp) == 0) {
		if (nbp->response[0] == '2') {
			/* Server granted access without password. */
			if (nbp->proxy == NULL)
				return (1);
			switch (nbp->pmeth) {
			case PROXY_USER_AT_HOST:
				/*
				 * We're connected through proxy so 220
				 * is the server banner response, so we
				 * insist on having 331 response to
				 * continue authentication or otherwise
				 * we bail out.
				 */
				(void)readresp('3', nbp);
				/* Does the server still need password? */
				if (nbp->response[0] == '2')
					return (1);
				if (nbp->response[0] != '3')
					return (0);
			}
		} else
			return (0);
	}
	snprintf(tempbuf, sizeof(tempbuf), "PASS %s", pass);
	return (ftp_send_cmd(tempbuf, '2', nbp));
}

/*
 * ftplib_access - send FTP command and return a handle for a
 *	data stream
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_access(const char *path, int typ, int mode, netbuf *nbp,
    netbuf **rnbp)
{
	char buf[256];
	int dir;

	if ((path == NULL) &&
	    ((typ == FTPLIB_FILE_WRITE) || (typ == FTPLIB_FILE_READ) ||
	     (typ == FTPLIB_FILE_APPE) || (typ == FTPLIB_FILE_REST))) {
		sprintf(nbp->response,
		    "Missing path argument for file transfer\n");
		return (0);
	}
	sprintf(buf, "TYPE %c", mode);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	switch (typ) {
	case FTPLIB_DIR:
		strcpy(buf, "NLST");
		dir = FTPLIB_READ;
		break;
	case FTPLIB_DIR_VERBOSE:
		strcpy(buf, "LIST");
		dir = FTPLIB_READ;
		break;
	case FTPLIB_FILE_REST:
		/* REST: Resuming support. */
		nbp->pxfer = FTP_REST;
		/* FALLTHRU */
	case FTPLIB_FILE_READ:
		strcpy(buf, "RETR");
		dir = FTPLIB_READ;
		break;
	case FTPLIB_FILE_WRITE:
		strcpy(buf, "STOR");
		dir = FTPLIB_WRITE;
		break;
	case FTPLIB_FILE_APPE:
		strcpy(buf, "APPE");
		dir = FTPLIB_WRITE;
		break;
	default:
		sprintf(nbp->response, "Invalid open type %d\n", typ);
		return (0);
	}
	if (path != NULL) {
		int i = strlen(buf);

		buf[i++] = ' ';
		/* Will it overflow? */
		if ((strlen(path) + i) >= sizeof(buf))
			return (0);
		strcpy(&buf[i], path);
	}
	/* Now issue approperiate PORT/PASV command */
	if (ftp_open_port(nbp, rnbp, mode, dir) == -1)
		return (0);
	if (ftp_send_cmd(buf, '1', nbp) == 0) {
		ftplib_close(*rnbp, 1);
		*rnbp = NULL;
		return (0);
	}
	if (nbp->cmode == FTPLIB_PORT) {
		if (ftp_accept_connection(*rnbp, nbp) == 0) {
			ftplib_close(*rnbp, 1);
			*rnbp = NULL;
			return (0);
		}
	}
	return (1);
}

/*
 * ftplib_read - read `max' bytes from a data connection
 */
DEFINE int
ftplib_read(void *buf, int max, netbuf *rnbp)
{
	int i;

	if (rnbp->dir != FTPLIB_READ)
		return (0);
	/* Are we in ASCII mode? */
	if (rnbp->buf != NULL)
		i = readline(buf, max, rnbp);
	else {
		socket_wait(rnbp);
		i = net_read(rnbp->handle, buf, max);
		/* TODO: check for errors here */
	}
	rnbp->xfered += i;
	/* Handle cbbytes callback */
	if (rnbp->xfercb != NULL && rnbp->cbbytes != 0) {
		rnbp->xfered1 += i;
		if (rnbp->xfered1 > rnbp->cbbytes) {
			while (rnbp->xfered1 > 0) {
				(*rnbp->xfercb)(rnbp, rnbp->xfered, 
				    rnbp->xferarg);
				rnbp->xfered1 -= rnbp->cbbytes;
			}
			if (rnbp->xfered1 < 0)
				rnbp->xfered1 = 0;
		}
	}
	return (i);
}

/*
 * ftplib_write - write `len' bytes to a data connection
 */
DEFINE int
ftplib_write(void *buf, int len, netbuf *rnbp)
{
	int i;

	if (rnbp->dir != FTPLIB_WRITE)
		return (0);
	/* Are we transfereing in ASCII mode? */
	if (rnbp->buf != NULL)
		i = writeline(buf, len, rnbp);
	else {
		socket_wait(rnbp);
		i = net_write(rnbp->handle, buf, len);
	}
	rnbp->xfered += i;
	/* Handle cbbytes callback */
	if (rnbp->xfercb != NULL && rnbp->cbbytes != 0) {
		rnbp->xfered1 += i;
		if (rnbp->xfered1 > rnbp->cbbytes) {
			while (rnbp->xfered1 > 0) {
				(*rnbp->xfercb)(rnbp, rnbp->xfered, 
				    rnbp->xferarg);
				rnbp->xfered1 -= rnbp->cbbytes;
			}
			if (rnbp->xfered1 < 0)
				rnbp->xfered1 = 0;
		}
	}
	return (i);
}

/*
 * ftplib_close - close a data connection.
 *
 * The parameter `error' indicates that we're closing to
 * errornous response from FTP server so we will not try to
 * read from the remote server `226' code.  This made ftplib
 * hangs for something like:
 * send> STOR some_file_with_wierd_chars
 * recv> 5XX file name is illegal
 * ... HANGS trying to read 2XX responses from server; the server
 * will not anything!
 */
DEFINE int
ftplib_close(netbuf *rnbp, int error)
{
	netbuf *ctrl;

	if (rnbp->dir == FTPLIB_WRITE) {
		if (rnbp->buf != NULL)
			writeline(NULL, 0, rnbp);
	} else if (rnbp->dir != FTPLIB_READ)
		return (0);
	if (rnbp->buf != NULL) {
		free(rnbp->buf);
		rnbp->buf = NULL;
	}
	shutdown(rnbp->handle, 2);
	net_close(rnbp->handle);
	ctrl = rnbp->ctrl;
	NBFREE(rnbp);
	if (error == 0 && ctrl)
		return (readresp('2', ctrl));
	return (1);
}

/*
 * ftplib_site - send a SITE command
 *
 * return 1 if command successful, 0 otherwise
 */
DEFINE int
ftplib_site(const char *cmd, netbuf *nbp)
{
	char buf[256];

	if ((strlen(cmd) + 7) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "SITE %s", cmd);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_systype - send a SYST command
 *
 * Fills in the user buffer with the remote system type.  If more
 * information from the response is required, the user can parse
 * it out of the response buffer returned by ftplib_last_response().
 *
 * return 1 if command successful, 0 otherwise
 */
DEFINE int
ftplib_systype(char *buf, int max, netbuf *nbp)
{
	int l = max;
	char *b = buf;
	char *s;

	if (ftp_send_cmd("SYST", '2', nbp) == 0)
		return (0);
	s = &nbp->response[4];
	while ((--l) && (*s != ' '))
		*b++ = *s++;
	*b++ = '\0';
	return (1);
}

/*
 * ftplib_mkdir - create a directory at server
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_mkdir(const char *path, netbuf *nbp)
{
	char buf[256];

	if ((strlen(path) + 6) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "MKD %s", path);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_chdir - change path at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_chdir(const char *path, netbuf *nbp)
{
	char buf[256];

	if ((strlen(path) + 6) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "CWD %s", path);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_cdup - move to parent directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_cdup(netbuf *nbp)
{

	if (ftp_send_cmd("CDUP", '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_rmdir - remove directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_rmdir(const char *path, netbuf *nbp)
{
	char buf[256];

	if ((strlen(path) + 6) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "RMD %s", path);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_pwd - get working directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_pwd(char *path, int max, netbuf *nbp)
{
	int l = max;
	char *b = path;
	char *s;

	if (ftp_send_cmd("PWD", '2', nbp) == 0)
		return (0);
	s = strchr(nbp->response, '"');
	if (s == NULL)
		return (0);
	s++;
	while ((--l) && (*s) && (*s != '"'))
		*b++ = *s++;
	*b++ = '\0';
	return (1);
}

/*
 * ftplib_nlst - issue an NLST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_nlst(const char *outputfile, const char *path,
    netbuf *nbp)
{

	return (ftp_xfer(outputfile, path, nbp, FTPLIB_DIR, FTPLIB_ASCII));
}

/*
 * ftplib_dir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_dir(const char *outputfile, const char *path, netbuf *nbp)
{

	return (ftp_xfer(outputfile, path, nbp,
	    FTPLIB_DIR_VERBOSE, FTPLIB_ASCII));
}

/*
 * ftplib_size - determine the size of a remote file
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_size(const char *path, size_t *size, char mode, netbuf *nbp)
{
	int resp, rv = 1;
	size_t sz;
	char cmd[256];

	if ((strlen(path) + 7) > sizeof(cmd))
		return (0);
	snprintf(cmd, sizeof(cmd), "TYPE %c", mode);
	if (ftp_send_cmd(cmd, '2', nbp) == 0)
		return (0);
	snprintf(cmd, sizeof(cmd), "SIZE %s", path);
	if (ftp_send_cmd(cmd, '2', nbp) == 0)
		rv = 0;
	else {
		if (sscanf(nbp->response, "%d %lu", &resp, 
		    (unsigned long *)&sz) == 2)
			*size = sz;
		else
			rv = 0;
	}
	return (rv);
}

/*
 * ftplib_moddate - determine the modification date of a remote file
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_moddate(const char *path, char *dt, int max, netbuf *nbp)
{
	char buf[256];
	int rv = 1;

	if ((strlen(path) + 7) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "MDTM %s", path);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		rv = 0;
	else
		strncpy(dt, &nbp->response[4], max);
	return (rv);
}

/*
 * ftplib_get - issue a GET command and write received data to output
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_get(const char *outputfile, const char *path,
    char mode, netbuf *nbp)
{

	return (ftp_xfer(outputfile, path, nbp, FTPLIB_FILE_READ, mode));
}

/*
 * ftplib_put - issue a PUT command and send data from input
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_put(const char *inputfile, const char *path, char mode,
    netbuf *nbp)
{

	return (ftp_xfer(inputfile, path, nbp, FTPLIB_FILE_WRITE, mode));
}

/*
 * ftplib_rename - rename a file at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_rename(const char *src, const char *dst, netbuf *nbp)
{
	char cmd[256];

	if (((strlen(src) + 7) > sizeof(cmd)) ||
	    ((strlen(dst) + 7) > sizeof(cmd)))
		return (0);
	snprintf(cmd, sizeof(cmd), "RNFR %s", src);
	if (ftp_send_cmd(cmd, '3', nbp) == 0)
		return (0);
	snprintf(cmd, sizeof(cmd), "RNTO %s", dst);
	if (ftp_send_cmd(cmd, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_delete - delete a file at remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_delete(const char *fnm, netbuf *nbp)
{
	char cmd[256];

	if ((strlen(fnm) + 7) > sizeof(cmd))
		return (0);
	sprintf(cmd, "DELE %s", fnm);
	if (ftp_send_cmd(cmd, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_quit - disconnect from remote
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE void
ftplib_quit(netbuf *nbp)
{

	if (nbp->dir != FTPLIB_CONTROL)
		return;
	ftp_send_cmd("QUIT", '2', nbp);
	net_close(nbp->handle);
	free(nbp->buf);
	nbp->buf = NULL;
	udebug(nbp, 1, "%lu bytes transfered\n", nbp->xfered);
	NBFREE(nbp);
	return;
}

DEFINE void
ftplib_set_debug_handler(netbuf *nbp, ftp_debug_callback udbg)
{

	dflt_debug = udbg;
	if (nbp != NULL)
		nbp->udebug = udbg;
	return;
}

/*
 * Local functions.
 */

/*
 * socket_wait - Wait for socket to receive or flush data. This will
 * be effective only if there is idle timeout.
 *
 * return 1 if no user callback, otherwise, return value returned by
 * user callback
 */
static int
socket_wait(netbuf *ctl)
{
	fd_set fd, *rfd = NULL, *wfd = NULL;
	struct timeval tv;
	int rv = 0;

	if ((ctl->dir == FTPLIB_CONTROL) || (ctl->idlecb == NULL))
		return (1);
	if (ctl->dir == FTPLIB_WRITE)
		wfd = &fd;
	else
		rfd = &fd;
	FD_ZERO(&fd);
	do {
		FD_SET(ctl->handle, &fd);
		tv = ctl->idletime;
		rv = select(ctl->handle + 1, rfd, wfd, NULL, &tv);
		if (rv == NET_ERR) {
			rv = 0;
			strncpy(ctl->ctrl->response, strerror(errno),
			    sizeof(ctl->ctrl->response));
			break;
		} else if (rv > 0) {
			rv = 1;
			break;
		}
	} while ((rv = (*ctl->idlecb)(ctl, ctl->idlearg)) != 0);
	return (rv);
}

/*
 * Read a line of text. used in FTP ASCII transfers.
 *
 * return -1 on error or bytecount
 */
static int
readline(char *buf, int max, netbuf *ctl)
{
	int x, retval = 0;
	char *end, *bp = buf;
	int eof = 0;

	/*
	 * make sure we are in control data connction.
	 */
	if ((ctl->dir != FTPLIB_CONTROL) && (ctl->dir != FTPLIB_READ))
		return (-1);
	if (max == 0)
		return (0);
	do {
		if (ctl->cavail > 0) {
			x = (max >= ctl->cavail) ? ctl->cavail : max - 1;
			end = memccpy(bp, ctl->cget, '\n', x);
			if (end != NULL)
				x = end - bp;
			retval += x;
			bp += x;
			*bp = '\0';
			max -= x;
			ctl->cget += x;
			ctl->cavail -= x;
			if (end != NULL) {
				bp -= 2;
				if (strcmp(bp, "\r\n") == 0) {
					*bp++ = '\n';
					*bp++ = '\0';
					--retval;
				}
				break;
			}
		}
		if (max == 1) {
			*buf = '\0';
			break;
		}
		/* Initial values (first read/buffer exausted) */
		if (ctl->cput == ctl->cget) {
			ctl->cput = ctl->cget = ctl->buf;
			ctl->cavail = 0;
			ctl->cleft = FTPLIB_BUFSIZ;
		}
		if (eof) {
			if (retval == 0)
				retval = -1;
			break;
		}
		if (!socket_wait(ctl))
			return (retval);
		if ((x = net_read(ctl->handle, ctl->cput,
		    ctl->cleft)) == NET_ERR) {
			derror("read");
			retval = -1;
			break;
		}
		if (x == 0)
			eof = 1;
		ctl->cleft -= x;
		ctl->cavail += x;
		ctl->cput += x;
	} while (1);
	return (retval);
}

/*
 * Write lines of text. used in FTP ASCII trasnfers.
 *
 * return -1 on error or bytecount
 */
static int
writeline(char *buf, int len, netbuf *nbp)
{
	int x, nb = 0, w;
	char *ubp = buf, *fbp;
	char lc = 0;

	if (nbp->dir != FTPLIB_WRITE)
		return (-1);
	fbp = nbp->buf;
	for (x = 0; x < len; x++) {
		if ((*ubp == '\n') && (lc != '\r')) {
			if (nb == FTPLIB_BUFSIZ) {
				if (!socket_wait(nbp))
					return x;
				w = net_write(nbp->handle,
				    fbp, FTPLIB_BUFSIZ);
				if (w != FTPLIB_BUFSIZ) {
					udebug(nbp, 0,
					    "net_write(1) returned %d, "
					    "errno = %d\n", w, errno);
					return (-1);
				}
				nb = 0;
			}
			fbp[nb++] = '\r';
		}
		if (nb == FTPLIB_BUFSIZ) {
			if (!socket_wait(nbp))
				return (x);
			w = net_write(nbp->handle, fbp, FTPLIB_BUFSIZ);
			if (w != FTPLIB_BUFSIZ) {
				udebug(nbp, 0, "net_write(2) returned %d, "
				    "errno = %d\n", w, errno);
				return (-1);
			}
			nb = 0;
		}
		fbp[nb++] = lc = *ubp++;
	}
	if (nb) {
		if (!socket_wait(nbp))
			return (x);
		w = net_write(nbp->handle, fbp, nb);
		if (w != nb) {
			udebug(nbp, 0,
			    "net_write(3) returned %d, errno = %d\n",
			    w, errno);
			return (-1);
		}
	}
	return (len);
}

/*
 * read a response from the server
 *
 * return 0 if first char doesn't match
 * return 1 if first char matches
 */
static int
readresp(char c, netbuf *nbp)
{
	char match[5];

	if (readline(nbp->response, sizeof(nbp->response), nbp) == -1) {
		derror("Control socket read failed");
		return (0);
	}
	udebug(nbp, 1, "%s", nbp->response);
	/* Read multiline response */
	if (nbp->response[3] == '-') {
		strncpy(match, nbp->response, 3);
		match[3] = ' ';
		match[4] = '\0';
		do {
			if (readline(nbp->response,
			    sizeof(nbp->response), nbp) == -1) {
				derror("Control socket read failed");
				return (0);
			}
			udebug(nbp, 1, "%s", nbp->response);
		} while (strncmp(nbp->response, match, 4));
	}
	if (nbp->response[0] == c)
		return (1);
	return (0);
}

/*
 * ftp_send_cmd - send a command and wait for expected response
 *
 * return 1 if proper response received, 0 otherwise
 */
static int
ftp_send_cmd(const char *cmd, char expresp, netbuf *nbp)
{
	char buf[256];

	if (nbp->dir != FTPLIB_CONTROL)
		return (0);
	udebug(nbp, 2, "%s\n", cmd);
	if ((strlen(cmd) + 3) > sizeof(buf))
		return (0);
	snprintf(buf, sizeof(buf), "%s\r\n", cmd);
	if (net_write(nbp->handle, buf, strlen(buf)) <= 0) {
		derror("write");
		return (0);
	}
	return (readresp(expresp, nbp));
}

/*
 * ftp_open_port - set up data connection
 *
 * return 1 if successful, 0 otherwise
 */
static int
ftp_open_port(netbuf *nbp, netbuf **rnbp, int mode, int dir)
{
	int sData;
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
	}     sin;
	struct linger lng = {0, 0};
	unsigned int l;
	int on = 1;
	netbuf *data;		/* Data connection */
	char *cp;
	unsigned int v[6];
	char buf[256];

	if (nbp->dir != FTPLIB_CONTROL)
		return (-1);
	if ((dir != FTPLIB_READ) && (dir != FTPLIB_WRITE)) {
		sprintf(nbp->response, "Invalid direction %d\n", dir);
		return (-1);
	}
	if ((mode != FTPLIB_ASCII) && (mode != FTPLIB_IMAGE)) {
		sprintf(nbp->response, "Invalid mode %c\n", mode);
		return (-1);
	}
	l = sizeof(sin);
	if (nbp->cmode == FTPLIB_PASSIVE) {
		memset(&sin, 0, l);
		sin.in.sin_family = AF_INET;
		if (!ftp_send_cmd("PASV", '2', nbp))
			return (-1);
		cp = strchr(nbp->response, '(');
		if (cp == NULL)
			return (-1);
		cp++;
		sscanf(cp, "%u,%u,%u,%u,%u,%u",
		    &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
		sin.sa.sa_data[2] = v[2];
		sin.sa.sa_data[3] = v[3];
		sin.sa.sa_data[4] = v[4];
		sin.sa.sa_data[5] = v[5];
		sin.sa.sa_data[0] = v[0];
		sin.sa.sa_data[1] = v[1];
	} else {
		if (getsockname(nbp->handle, &sin.sa, &l) < 0) {
			derror("getsockname");
			return (0);
		}
	}
	sData = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sData == SOCKET_CALL_ERR) {
		derror("socket");
		return (-1);
	}
	if (setsockopt(sData, SOL_SOCKET, SO_REUSEADDR,
		SETSOCKOPT_OPTVAL_TYPE & on, sizeof(on)) == NET_ERR) {
		derror("setsockopt");
		net_close(sData);
		return (-1);
	}
	if (setsockopt(sData, SOL_SOCKET, SO_LINGER,
		SETSOCKOPT_OPTVAL_TYPE &lng, sizeof(lng)) == NET_ERR) {
		derror("setsockopt");
		net_close(sData);
		return (-1);
	}
	if (nbp->cmode == FTPLIB_PASSIVE) {
		if (connect(sData, &sin.sa, sizeof(sin.sa)) == NET_ERR) {
			derror("connect");
			net_close(sData);
			return (-1);
		}
	} else {
		sin.in.sin_port = 0;
		if (bind(sData, &sin.sa, sizeof(sin)) == NET_ERR) {
			derror("bind");
			net_close(sData);
			return (0);
		}
		if (listen(sData, 1) == NET_ERR) {
			derror("listen");
			net_close(sData);
			return (0);
		}
		if (getsockname(sData, &sin.sa, &l) < 0)
			return (0);
		sprintf(buf, "PORT %d,%d,%d,%d,%d,%d",
		    (unsigned char) sin.sa.sa_data[2],
		    (unsigned char) sin.sa.sa_data[3],
		    (unsigned char) sin.sa.sa_data[4],
		    (unsigned char) sin.sa.sa_data[5],
		    (unsigned char) sin.sa.sa_data[0],
		    (unsigned char) sin.sa.sa_data[1]);
		if (ftp_send_cmd(buf, '2', nbp) == 0) {
			net_close(sData);
			return (0);
		}
	}
	data = calloc(1, sizeof(netbuf));
	if (data == NULL) {
		derror("calloc");
		net_close(sData);
		return (-1);
	}
	/*
	 * Allocated->buf only in ASCII transfers to so that XXX_read
	 * calls read_line instead of net_read.
	 */
	if ((mode == 'A') && ((data->buf = malloc(FTPLIB_BUFSIZ)) == NULL)) {
		derror("calloc");
		net_close(sData);
		free(data);
		return (-1);
	}
	/* Handle pre transfer commands. */
	switch (nbp->pxfer) {
	case FTP_REST:
		/* First send REST XXXX command */
		snprintf(buf, sizeof(buf), "REST %lu", 
		    (unsigned long)nbp->restoff);
		if (ftp_send_cmd(buf, '3', nbp) == 0)
			return (0);
		break;
	default:
		break;
	}
	/* 
	 * Reset pre transfer commands so it doesn't interfer with 
	 * subsequant service commands.
	 */
	nbp->pxfer = 0;
	/* Data connection socket. */
	data->handle = sData;
	data->dir = dir;
	data->ctrl = (nbp->cmode == FTPLIB_PASSIVE) ? nbp : NULL; /* ? */
	data->idletime = nbp->idletime;
	data->idlearg = nbp->idlearg;
	data->xfered = 0;
	data->xfered1 = 0;
	data->cbbytes = nbp->cbbytes;
	data->udebug = nbp->udebug;
	if (data->idletime.tv_sec | data->idletime.tv_usec)
		data->idlecb = nbp->idlecb;
	else
		data->idlecb = NULL;
	data->xfercb = nbp->xfercb;
	data->xferarg = nbp->xferarg;
	*rnbp = data;
	return (1);
}

/*
 * ftp_accept_connection - accept connection from server
 *
 * return 1 if successful, 0 otherwise
 */
static int
ftp_accept_connection(netbuf *rnbp, netbuf *nbp)
{
	int sData;
	struct sockaddr addr;
	unsigned int l;
	int i;
	struct timeval tv;
	fd_set mask;
	int rv;

	FD_ZERO(&mask);
	FD_SET(nbp->handle, &mask);
	FD_SET(rnbp->handle, &mask);
	tv.tv_usec = 0;
	tv.tv_sec = ACCEPT_TIMEOUT;
	i = nbp->handle;
	if (i < rnbp->handle)
		i = rnbp->handle;
	i = select(i + 1, &mask, NULL, NULL, &tv);
	if (i == NET_ERR) {
		strncpy(nbp->response, strerror(errno),
		    sizeof(nbp->response));
		net_close(rnbp->handle);
		rnbp->handle = 0;
		rv = 0;
	} else if (i == 0) {
		strcpy(nbp->response, "timed out waiting for connection");
		net_close(rnbp->handle);
		rnbp->handle = 0;
		rv = 0;
	} else {
		if (FD_ISSET(rnbp->handle, &mask)) {
			l = sizeof(addr);
			sData = accept(rnbp->handle, &addr, &l);
			i = errno;
			net_close(rnbp->handle);
			if (sData > 0) {
				rv = 1;
				rnbp->handle = sData;
				rnbp->ctrl = nbp;
			} else {
				strncpy(nbp->response, strerror(i),
				    sizeof(nbp->response));
				rnbp->handle = 0;
				rv = 0;
			}
		} else if (FD_ISSET(nbp->handle, &mask)) {
			net_close(rnbp->handle);
			rnbp->handle = 0;
			readresp('2', nbp);
			rv = 0;
		} else
			rv = 0;	/* Shouldn't happen, but fail anyway. */
	}
	return (rv);
}

/*
 * ftp_xfer - issue a command and transfer data
 *
 * return 1 if successful, 0 otherwise
 */
static int
ftp_xfer(const char *localfile, const char *path,
    netbuf *nbp, int typ, int mode)
{
	int l, c;
	char *dbuf, *omode;
	FILE *local = NULL;
	netbuf *rnbp;

	if (localfile != NULL) {
		switch (typ) {
		case FTPLIB_FILE_WRITE:
			omode = "r";
			break;
		case FTPLIB_FILE_REST:
			omode = "a";
			break;
		default:
			omode = "w";
			break;
		}
		local = fopen(localfile, omode);
		if (local == NULL) {
			strncpy(nbp->response, strerror(errno),
			    sizeof(nbp->response));
			return (0);
		}
		/* REST/APPE: Resuming support. */
		if (typ == FTPLIB_FILE_REST) {
			fseek(local, 0, SEEK_END);
		} else if (typ == FTPLIB_FILE_APPE) {
			fseek(local, nbp->restoff, SEEK_SET);
		}
	}
	if (local == NULL)
		local = (typ == FTPLIB_FILE_WRITE) ? stdin : stdout;
	if (ftplib_access(path, typ, mode, nbp, &rnbp) == 0)
		return (0);
	dbuf = malloc(FTPLIB_BUFSIZ);
	if (typ == FTPLIB_FILE_WRITE || typ == FTPLIB_FILE_APPE) {
		while ((l = fread(dbuf, 1, FTPLIB_BUFSIZ, local)) > 0)
			if ((c = ftplib_write(dbuf, l, rnbp)) < l)
				udebug(nbp, 0,
				    "short write: passed %d, wrote %d\n",
				    l, c);
	} else {
		while ((l = ftplib_read(dbuf, FTPLIB_BUFSIZ, rnbp)) > 0)
			if (fwrite(dbuf, 1, l, local) <= 0) {
				derror("localfile write");
				break;
			}
	}
	free(dbuf);
	fflush(local);
	if (localfile != NULL)
		fclose(local);
	/* 
	 * Refelect how many bytes involved in this transfer
	 * for this FTP connection.
	 */
	nbp->xfered += rnbp->xfered;
	return (ftplib_close(rnbp, 0));
}

static void
udebug(netbuf *nbp, int level, const char *fmt, ...)
{
	va_list args;
	char vbuf[BUFSIZ];

	if (ftplib_debug == 0)
		return;
	if (ftplib_debug < level)
		return;
	va_start(args, fmt);
	vsprintf(vbuf, fmt, args);
	va_end(args);
	if (nbp != NULL && nbp->udebug != NULL)
		(*nbp->udebug)(vbuf);
	else if (dflt_debug != NULL)
		(*dflt_debug)(vbuf);
	else
		fprintf(stderr, "%s", vbuf);
	return;
}

void
derror(const char *msg)
{

	if (ftplib_debug > 1)
		udebug(NULL, 0, "%s:%d: %s\n", msg, errno, strerror(errno));
	else
		udebug(NULL, 0, "%s: %s\n", msg, strerror(errno));
	return;
}

/*
 * Parsing FTP directory entry from `LIST' comamnd output.  Code written
 * from scratch.
 */

DEFINE int
__ftp_test()
{
	struct ftp_list_entry *unix_listing_parse(char *fline);

	return (unix_listing_parse(
	    /*"-rw-r--r--   1 root     other        531 Jan 29 03:26 README"*/
	    /*"dr-xr-xr-x   2 root     other        512 Apr  8  1994 etc"*/
	    /*"dr-xr-xr-x   2 root     1002         512 Apr 14  1994 junk"*/
	    /*"dr-xr-xr-x   2 root                  512 Apr  8  1994 etc"*/
	    /*"lrwxrwxrwx   1 root     other        7 Jan 25 00:17 bin -> usr/bin"*/
	    "----------   1 owner	group         1803128 Jul 10 10:18 ls-lR.Z"
	    ) != NULL);
}

/* UNIX-style listing, without inum and without blocks */
/* "-rw-r--r--   1 root     other        531 Jan 29 03:26 README" */
/* "dr-xr-xr-x   2 root     other        512 Apr  8  1994 etc" */
/* "dr-xr-xr-x   2 root     1002         512 Apr 14  1994 junk" */
/* "dr-xr-xr-x   2 root                  512 Apr  8  1994 etc" */
/* "lrwxrwxrwx   1 root     other        7 Jan 25 00:17 bin -> usr/bin" */
/* Also produced by Microsoft's FTP servers for Windows: */
/* "----------   1 owner    group         1803128 Jul 10 10:18 ls-lR.Z" */
/* "d---------   1 owner    group               0 May  9 19:45 Softlib" */

/*
 * 1- permissions
 * 2- hard links count
 * 3- user name/id
 * 4- group name/id (optional)
 * 5- size
 * 6- Last modification time (starts with month appr.)
 * 7- name
 */
#define SKIP_SINGLE_SPACE(p) do { \
	if (*(p) == ' ' || *(p) == '\t') \
		(p)++; \
} while (0)

#define SKIP_SINGLE_DIGIT(d) do { \
	if (isdigit(*(d)) != 0) \
		(d)++; \
} while (0)

void 
fle_dump(struct ftp_list_entry *fle)
{
	udebug(NULL, 0, "type=%d\n", fle->fle_etype);
	udebug(NULL, 0, "perm=%s\n", fle->fle_perm);
	udebug(NULL, 0, "owner=%s\n", fle->fle_owner);
	udebug(NULL, 0, "grp=%s\n", fle->fle_grp);
	udebug(NULL, 0, "size=%d\n", fle->fle_size);
	udebug(NULL, 0, "time=%d\n", fle->fle_mtime);
	udebug(NULL, 0, "s_time=%s\n", fle->fle_smtime);
	udebug(NULL, 0, "name=%s\n", fle->fle_name);
	return;
}

DEFINE struct ftp_list_entry *
ftplib_listing_parse(char *fline)
{

	return (unix_listing_parse(fline));
}

/*
 * Should be exist: SKIP_SINGLE_DIGIT_ERR that will error if not digit.
 */
struct ftp_list_entry *
unix_listing_parse(char *fline)
{
	register char *p, *ps, *pt;
	register struct ftp_list_entry *fle;

	/* A very stupid check */
	if (strlen(fline) < 30)
		return (NULL);
	if ((fle = malloc(sizeof(struct ftp_list_entry))) == NULL) {
		udebug(NULL, 0, "listing_parse:1: out of memory\n");
		return (NULL);
	}
	memset(fle, 0, sizeof(struct ftp_list_entry));
	p = fline;
	switch (*p++) {
	case 'd':
		fle->fle_etype = ETYPE_DIR;
		break;
	case 'l':
		fle->fle_etype = ETYPE_SYMLINK;
		break;
		/* FALLTHRU */
	case 'c':
	case 'b':
		fle->fle_etype = ETYPE_DEVICE;
		break;
	case '-':
		fle->fle_etype = ETYPE_FILE;
		break;
	default:
		free(fle);
		return (NULL);
	}
	strncpy(fle->fle_perm, p, 9);
	p += 9;
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	/* XXX Skip the hard link count portion */
	while (isdigit(*p) != 0)
		p++;
	if (*p == 0) {
		free(fle);
		return (NULL);
	}
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	/* User ID */
	if (isalpha(*p)  == 0) {
		udebug(NULL, 0, "listing_parse: expected user ID at %s\n",
		    p);
		free(fle);
		return (NULL);
	}
	ps = p;
	while (isalnum(*p) != 0)
		p++;
	strncpy(fle->fle_owner, ps, 
	    p - ps < sizeof(fle->fle_owner) ? 
	    p - ps : sizeof(fle->fle_owner) - 1);
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	/* Group ID */
	if (isalpha(*p) != 0) {
		/* We have group name */
		ps = p;
		while (isalnum(*p) != 0)
			p++;
		strncpy(fle->fle_grp, ps, 
		    p - ps < sizeof(fle->fle_grp) ?
		    p - ps : sizeof(fle->fle_grp) - 1);
	} else {
		char *f1, *rollback;
		
		if (isdigit(*p) == 0) {
			udebug(NULL, 0, "listing_parse: expected numeric "
			    "in group field at %s\n", p);
			free(fle);
			return (NULL);
		}
		/*
		 * We have a digit in group name field, so it might
		 * be a group numeric value, or the size of the entry
		 * if the group is ommited.
		 * We can decide of these cases by checking the next
		 * field start character, which is numeric (size) if
		 * out digit represents group value, or an alphabetic
		 * character (month name of modification time) if our
		 * digit represents entry size.
		 */
		pt = p;
		rollback = p;
		while (*p != ' ' && *p != '\t' && *p != 0)
			p++;
		f1 =  p;
		if (*f1 == 0) {
			udebug(NULL, 0, "listing_parse:1: EOL not expected\n");
			free(fle);
			return (NULL);
		}
		while ((*p == ' ' || *p == '\t') && *p != 0)
			p++;
		if (isdigit(*p) != 0) {
			/* p at size field now */
			strncpy(fle->fle_grp, pt, 
			    f1 - pt < sizeof(fle->fle_grp) ?
			    f1 - pt : sizeof(fle->fle_grp) - 1);
		} else {
			/* 
			 * p at mod_time now, we need to rollback to
			 * to last field (size).
			 */
			p = rollback;
		}
		udebug(NULL, 3, "REMOVEME: size at %s\n", p);
	}
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	/* Size */
	if (isdigit(*p) == 0) {
		udebug(NULL, 0, "listing_parse: expected size at %s\n", p);
		free(fle);
		return (NULL);
	}
	fle->fle_size = atoi(p);
	/* Now skip the size */
	while (isdigit(*p) != 0)
		p++;
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	if (*p == 0) {
		udebug(NULL, 0, "listing_parse:2: EOL not expected\n");
		free(fle);
		return (NULL);
	}
	/* Modification time */
	ps = p;
	if (isalpha(*(p + 0)) == 0 || isalpha(*(p + 1)) == 0 ||
	    isalpha(*(p + 2)) == 0) {
		udebug(NULL, 0, 
		    "listing_parse: expected month name at %s\n", p);
		free(fle);
		return (NULL);
	}
	p += 3;
	SKIP_SINGLE_SPACE(p);
	SKIP_SINGLE_SPACE(p);
	/* Now we have the day; try to skip one/two digit(s) */
	SKIP_SINGLE_DIGIT(p);
	SKIP_SINGLE_DIGIT(p);
	if (isspace(*p) == 0) {
		udebug(NULL, 0, "listing_parse: expected space at %s\n", p);
		free(fle);
		return (NULL);
	}
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	/* Now we try to match a year YY/YYYY or a time HH:MM */
	SKIP_SINGLE_DIGIT(p);
	SKIP_SINGLE_DIGIT(p);
	if (*p == ':') {
		p++;
		/* time */
		SKIP_SINGLE_DIGIT(p);
		SKIP_SINGLE_DIGIT(p);
	} else if (*p != ' ' || *p != '\t') {
		/* four digits year */
		SKIP_SINGLE_DIGIT(p);
		SKIP_SINGLE_DIGIT(p);
	}
	strncpy(fle->fle_smtime, ps, p - ps < sizeof(fle->fle_smtime) ? 
	    p - ps : sizeof(fle->fle_smtime) - 1);
	while ((*p == ' ' || *p == '\t') && *p != 0)
		p++;
	if (*p == 0) {
		udebug(NULL, 0, "listing_parse:3: unexpected EOL\n");
		free(fle);
		return (NULL);
	}
	/* The rest is the file name */
	strncpy(fle->fle_name, p, sizeof(fle->fle_name));
	fle_dump(fle);
	return (fle);
}

/*
 * ftplib_help - Requst information from remote server (about
 * implementation status).
 * If supplied with command name (cmd != NULL) then server
 * will respond with more information regarding this command.
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_help(const char *cmd, netbuf *nbp)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "HELP%s%s",
	    cmd == NULL ? "" : " ",
	    cmd == NULL ? "" : cmd);
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_abort - Tell the server to abort previous service
 * command and any associated trasfers of data.
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_abort(netbuf *nbp)
{
	char buf[5];

	snprintf(buf, sizeof(buf), "ABOR");
	if (ftp_send_cmd(buf, '2', nbp) == 0)
		return (0);
	return (1);
}

/*
 * ftplib_set_restoff - Used before calling ftplib_access to intiate
 * restart session (FTPLIB_FILE_REST) so that ftplib_access can send
 * approperiate REST XXXX command before returning data connection
 * handle to caller.
 *
 * NOTE: ftplib_access impilicity calls ftp_open_port() to open data
 * connection to remote host, which will send `REST' command.
 *
 * return nothing
 */
DEFINE void
ftplib_set_restoff(size_t restoff, netbuf *nbp)
{

	nbp->restoff = restoff;
	return;
}

/*
 * ftplib_resume - Restart downloading a file.
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int 
ftplib_resume(const char *output, const char *path, char mode, netbuf *nbp)
{
	size_t rsz;	/* Remote file size */
	FILE *f;

	if ((f = fopen(output, "r")) != NULL) {
		if (fseek(f, 0, SEEK_END) < 0) {
			fclose(f);
			return (0);
		}
		nbp->restoff = ftell(f);
		fclose(f);
	} else
		nbp->restoff = 0;
	if (ftplib_size(path, &rsz, mode, nbp) == 0)
		return (0);
	if (nbp->restoff > rsz) {
		udebug(nbp, 0, 
		    "ftplib_resume(%s): local file is smaller than %s start "
		    "offset (%lu/%lu)\n",
		    (unsigned long)rsz, (unsigned long)nbp->restoff);
		return (0);
	} else if (rsz == nbp->restoff)
		return (1);
	return (ftp_xfer(output, path, nbp, FTPLIB_FILE_REST, mode));
}

/*
 * ftplib_version - Return brief/long version of the library.
 *
 * Always successful.
 */
DEFINE char *
ftplib_version(int vertype)
{

	if (vertype == FTPLIB_VER_BRIEF)
		return (VERSION);
	return (version);
}

/*
 * ftplib_set_debug - Set log level.
 * See FTPLIB_LOG_XXX
 * 
 * No return.
 */
DEFINE void 
ftplib_set_debug(int debug)
{

	ftplib_debug = debug;
	return;
}

/*
 * ftplib_append - If remote file exist and is less in size than local file
 * append to remote file what's left.
 *
 * return 1 if successful, 0 otherwise
 */
DEFINE int
ftplib_append(const char *localfile, const char *path, char mode, netbuf *nbp)
{
	size_t rsz;
	struct stat sb;

	nbp->restoff = 0;
	if (ftplib_size(path, &rsz, mode, nbp) != 0) {
		if (stat(localfile, &sb) < 0) {
			derror(localfile);
			return (0);
		}
		if (sb.st_size < rsz) {
			udebug(nbp, 2, "ftplib_append(%s): local file size "
			    "(%lu) is less than remote (%lu).  No action "
			    "taken\n", localfile, sb.st_size, rsz);
			return (0);
		}
		/* No need to do it */
		if (sb.st_size == rsz)
			return (1);
		nbp->restoff = rsz;
	}
	return (ftp_xfer(localfile, path, nbp, FTPLIB_FILE_APPE, mode));
}
