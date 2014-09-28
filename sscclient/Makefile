# Makefile for sscclient

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	sscclient

install:	$(BIN)/sscclient

SSCCLIENT_OS=	os_minix.o
SSCCLIENT_OBJ=	dh.o rsa.o sscclient.o $(SSCCLIENT_OS)
SSCCLIENT_LIB=	../lib/libcrypt.a ../lib/libos.a

sscclient:	$(SSCCLIENT_OBJ) $(SSCCLIENT_LIB)
	$(CC) -o $@ $(SSCCLIENT_OBJ) $(SSCCLIENT_LIB)

$(BIN)/sscclient:	sscclient
	$(INSTALL) sscclient $@

clean:
	rm -f sscclient $(SSCCLIENT_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:23:01 philip Exp $
