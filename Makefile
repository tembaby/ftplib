#
# This makefile contains modifications submitted by Richard Braakman
# (dark@xs4all.nl) for the shared library generation.
#
# Deeply changed for BSD make.  Tamer Embaby <tsemba@menanet.net>.
#

# By default, ftplib uses PASV.  If you need it to use  PORT
# instead, uncomment the next line
DEFINES		= -DFTPLIB_DEFMODE=FTPLIB_PORT

SONAME		= 3
SOVER		= $(SONAME).1

TARGETS		= libftp.a libftp.so.$(SOVER)
SOOBJ		= ftplib-shared.o
STOBJ		= ftplib-static.o
OBJECTS		= $(STOBJ) $(SOOBJ)
SOURCES		= ftplib.c
INCLUDES	=

CFLAGS		= -Wall $(DEBUG) -I. $(INCLUDES) $(DEFINES)
LDFLAGS		= -L.

all		: $(TARGETS)

clean		: clean_test
	rm -f $(OBJECTS) *.core $(TARGETS)

$(STOBJ)	: ftplib.c ftplib.h
	$(CC) -c $(CFLAGS) $(SOURCES) -o $(STOBJ)

$(SOOBJ)	: ftplib.c ftplib.h
	$(CC) -c $(CFLAGS) -fPIC $(SOURCES) -o $(SOOBJ)

libftp.a	: $(STOBJ)
	ar -rc $@ $(STOBJ)

libftp.so.$(SOVER)	: $(SOOBJ)
	$(CC) -shared -Wl,-soname,libftp.so.$(SONAME) -lc -o $@ $(SOOBJ)

main.o			: main.c
	$(CC) -c $(CFLAGS) main.c

ftptest			: main.o
	$(CC) $(CFLAGS) -o $@ main.o -L. -lftp

clean_test		:
	-rm -f ftptest libftp.a main.o

test			: clean_test libftp.a ftptest
	./ftptest

static			: libftp.a

shared			: libftp.so.$(SOVER)
