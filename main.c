/* $Id: main.c,v 1.5 2002/10/07 02:40:04 te Exp $ */

#include <stdio.h>
#include <unistd.h>

#include <ftplib.h>

void	mydebug(const char *);
int	mycallback(netbuf *,int,void*);

int
main()
{
	size_t fsize;
	netbuf *ftp;
	char path[BUFSIZ];
	char buf[BUFSIZ];

	printf("Ftplib: %s\n", ftplib_version(FTPLIB_VERSION));
	ftplib_set_debug(FTPLIB_LOG_HARDCORE);
	ftplib_init();
	ftplib_set_debug_handler(NULL, mydebug);

#if 0
	if (__ftp_test() != NULL)
		printf("DONE\n");
	else
		printf("FAILED\n");
	return (0);
#endif

	if (ftplib_connect("localhost" /*"ftp.openbsd.org"*/, 
	    NULL /*"192.168.2.1:21"*/,
	    &ftp) == 0)
		return (0);
	ftplib_set_debug_handler(ftp, mydebug);
	if (ftplib_login("te", "tott", ftp) == 0)
		return (0);
	ftplib_pwd(path, sizeof(path), ftp);
	ftplib_systype(buf, sizeof(buf), ftp);
	ftplib_options(FTPLIB_XFERCALLBACK, (long)mycallback, ftp);
	ftplib_options(FTPLIB_CALLBACKBYTES, 1, ftp);
	ftplib_size("etc.tgz", &fsize, FTPLIB_BINARY, ftp);
	ftplib_options(FTPLIB_XFERCALLBACKARG, (long)&fsize, ftp);
	ftplib_help("EPRT", ftp);
	ftplib_help("EPSV", ftp);
	//ftplib_resume("etc.tgz", "etc.tgz", FTPLIB_BINARY, ftp);
	ftplib_append("etc.tgz", "etc.tgz", FTPLIB_BINARY, ftp);
	ftplib_quit(ftp);
	return (0);
}

void
mydebug(const char *msg)
{

	fprintf(stderr, "%s", msg);
	return;
}

int 
mycallback(netbuf *nbp, int xfered, void *arg)
{
	int prec;
	size_t total;

	if (arg == NULL)
		fprintf(stderr, "#");
	else {
		total = *(size_t *)arg;
		prec = (xfered * 100) / total;
		fprintf(stderr, "download: %3d%%\r", prec);
	}
	return (0);
}
