# Makefile for sscrcpd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

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
# $PchId: Makefile,v 1.3 2011/12/28 11:47:54 philip Exp $
