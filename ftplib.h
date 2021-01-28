/* $Id: ftplib.h,v 1.11 2004/04/21 22:35:12 te Exp $ */

/***************************************************************************/
/*									   */
/* ftplib.h - header file for callable ftp access routines                 */
/* Copyright (C) 1996, 1997 Thomas Pfau, pfau@cnj.digex.net                */
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
/*									   */
/***************************************************************************/

/*
 * ftplib.h v4.0, Sept. 2002, 2003, 2004.
 * Tamer Embaby <tsemba@menanet.net>
 */

#if !defined (__FTPLIB_H)
# define __FTPLIB_H

#if defined (__unix__)
# define DEFINE
# define PROTO		extern
#elif defined (_WIN32)	/* __unix__ */
# if defined (BUILDING_LIBRARY)
#  define DEFINE	__declspec(dllexport)
#  define PROTO		__declspec(dllexport)
# else	/* BUILDING_LIBRARY */
#  define PROTO		__declspec(dllimport)
# endif
#endif	/* _WIN32 */

#if 0
/*
 * File offsets.
 */
#define HAVE_SEEKO	1	/* OFF_T width=64 */
#define HAVE_FSETPOS	1	/* OFF_T width=32, OFF_T_WIDTH=64 */
#define USE_ANSI_CALLS	1	/* OFF_T width=32 */
#endif

/* ftplib_version */
#define FTPLIB_VER_FULL		0
#define FTPLIB_VER_BRIEF	1
#define FTPLIB_VERSION		FTPLIB_VER_FULL

/* ftplib_access() type codes */
#define FTPLIB_DIR		1
#define FTPLIB_DIR_VERBOSE	2
#define FTPLIB_FILE_READ	3
#define FTPLIB_FILE_WRITE	4
#define FTPLIB_FILE_REST	5
#define FTPLIB_FILE_APPE	6

/* ftplib_access() mode codes */
#define FTPLIB_ASCII		'A'
#define FTPLIB_IMAGE		'I'
#define FTPLIB_TEXT		FTPLIB_ASCII
#define FTPLIB_BINARY		FTPLIB_IMAGE

/* connection modes */
#define FTPLIB_PASSIVE		1
#define FTPLIB_PORT		2

/* connection option names */
#define FTPLIB_CONNMODE		1
#define FTPLIB_IDLECALLBACK	2
#define FTPLIB_IDLETIME		3
#define FTPLIB_IDLECALLBACKARG	4
#define FTPLIB_CALLBACKBYTES	5
#define FTPLIB_XFERCALLBACK	6
#define FTPLIB_XFERCALLBACKARG	7

/* Error levels */
#define FTPLIB_LOG_NORMAL	0
#define FTPLIB_LOG_SERVER	1
#define FTPLIB_LOG_CLIENT	2
#define FTPLIB_LOG_HARDCORE	3

#if defined (_WIN32)
# define _POSIX_
#endif
#include <limits.h>
#if defined (_WIN32) || defined (sun)
# include <bsd_list.h>
#else
# include <sys/queue.h>
#endif

struct ftp_list_entry {
	TAILQ_ENTRY(ftp_list_entry)
		fle_link;
	u_char	fle_etype;		/* Entry type */
#define ETYPE_FILE	1
#define ETYPE_DIR	2
#define ETYPE_SYMLINK	3
#define ETYPE_DEVICE	4
	char	fle_perm[10];		/* Premissions as rwxr-xr-- */
	char	fle_owner[64];		/* Owner if the entry */
	char	fle_grp[64];		/* Group name */
	size_t	fle_size;
	time_t	fle_mtime;		/* Not used */
	char	fle_smtime[16];		/* Modification time/date */
	char	fle_name[PATH_MAX];
};
TAILQ_HEAD(ftp_list_t, ftp_list_entry);

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _netbuf netbuf;
typedef int (*ftp_idle_callback)(netbuf *,void *);
typedef void (*ftp_xfer_callback)(netbuf *,int,void *);
typedef void (*ftp_debug_callback)(const char *);

PROTO	int ftplib_debug;
PROTO	void ftplib_init(void);
PROTO	void ftplib_deinit(void);
PROTO	char *ftplib_last_response(netbuf *);
PROTO	int ftplib_connect(const char *,const char *,netbuf **);
PROTO	int ftplib_options(int,long,netbuf *);
PROTO	int ftplib_login(const char *,const char *,netbuf *);
PROTO	int ftplib_access(const char *,int,int,netbuf *,netbuf **);
PROTO	int ftplib_read(void *,int,netbuf *);
PROTO	int ftplib_write(void *,int,netbuf *);
PROTO	int ftplib_close(netbuf *,int);
PROTO	int ftplib_site(const char *,netbuf *);
PROTO	int ftplib_systype(char *,int,netbuf *);
PROTO	int ftplib_mkdir(const char *,netbuf *);
PROTO	int ftplib_chdir(const char *,netbuf *);
PROTO	int ftplib_cdup(netbuf *);
PROTO	int ftplib_rmdir(const char *,netbuf *);
PROTO	int ftplib_pwd(char *,int,netbuf *);
PROTO	int ftplib_nlst(const char *,const char *,netbuf *);
PROTO	int ftplib_dir(const char *,const char *,netbuf *);
PROTO	int ftplib_size(const char *,size_t *,char,netbuf *);
PROTO	int ftplib_moddate(const char *,char *,int,netbuf *);
PROTO	int ftplib_get(const char *,const char *,char,netbuf *);
PROTO	int ftplib_put(const char *,const char *,char,netbuf *);
PROTO	int ftplib_rename(const char *,const char *,netbuf *);
PROTO	int ftplib_delete(const char *,netbuf *);
PROTO	int ftplib_help(const char *,netbuf *);
PROTO	int ftplib_abort(netbuf *);
PROTO	void ftplib_quit(netbuf *);
PROTO	void ftplib_set_restoff(size_t,netbuf *);
PROTO	int ftplib_resume(const char *,const char *,char,netbuf *);
PROTO	int ftplib_append(const char *,const char *,char,netbuf *);
PROTO	char *ftplib_version(int);
PROTO	void ftplib_set_debug(int);
PROTO	void ftplib_set_debug_handler(netbuf *,ftp_debug_callback);
PROTO	struct ftp_list_entry *ftplib_listing_parse(char *);

PROTO	int __ftp_test(void);

#ifdef __cplusplus
};
#endif

#endif /* __FTPLIB_H */
