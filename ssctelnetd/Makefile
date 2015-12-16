# Makefile for ssctelnetd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

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
# $PchId: Makefile,v 1.3 2011/12/28 11:48:38 philip Exp $
