# Makefile for sscrcpd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	sscrcpd

install: $(BIN)/sscrcpd
	
#SSCRCPD_OS=	os_minix.o
SSCRCPD_OBJ=	sscrcpd.o $(SSCRCPD_OS)
SSCRCPD_LIB=	../lib/libos.a

sscrcpd:	$(SSCRCPD_OBJ) $(SSCRCPD_LIB)
	$(CC) -o $@ $(SSCRCPD_OBJ) $(SSCRCPD_LIB)

$(BIN)/sscrcpd: sscrcpd
	$(INSTALL) sscrcpd $@

clean:
	rm -f sscrcpd $(SSCRCPD_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:18:02 philip Exp $
