# Makefile for sscclient

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=$(ARCH_FLAGS) -I../include

all:	sscclient

install:	$(BIN)/sscclient

SSCCLIENT_OS=	os.o
SSCCLIENT_OBJ=	dh.o rsa.o sscclient.o $(SSCCLIENT_OS)
SSCCLIENT_LIB=	../lib/libcrypt.a ../lib/libos.a

sscclient:	$(SSCCLIENT_OBJ) $(SSCCLIENT_LIB)
	$(CC) -o $@ $(CFLAGS) $(SSCCLIENT_OBJ) $(SSCCLIENT_LIB) $(OS_LIBS)

$(BIN)/sscclient:	sscclient
	$(INSTALL) sscclient $@

os.o: os_minix.c os_linux.c os_posix.c

clean:
	rm -f sscclient $(SSCCLIENT_OBJ)

#
# $PchId: Makefile,v 1.4 2011/12/29 20:20:52 philip Exp $
