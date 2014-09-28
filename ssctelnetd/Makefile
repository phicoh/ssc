# Makefile for ssctelnetd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	ssctelnetd

install: $(BIN)/ssctelnetd

#SSCTELNETD_OS=	os_minix.o
SSCTELNETD_OBJ=	ssctelnetd.o $(SSCTELNETD_OS)
SSCTELNETD_LIB=	../lib/libos.a

ssctelnetd:	$(SSCTELNETD_OBJ) $(SSCTELNETD_LIB)
	$(CC) -o $@ $(SSCTELNETD_OBJ) $(SSCTELNETD_LIB)

$(BIN)/ssctelnetd: ssctelnetd
	$(INSTALL) ssctelnetd $@

clean:
	rm -f ssctelnetd $(SSCTELNETD_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:16:06 philip Exp $
