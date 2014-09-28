# Makefile for sscserver

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

ETC_SSC=/etc/ssc

all:	sscserver

install: $(BIN)/sscserver $(ETC_SSC)/services

SSCSERVER_OS=	os_minix.o
SSCSERVER_OBJ=	auth.o dh.o rsa.o service.o sscserver.o $(SSCSERVER_OS)
SSCSERVER_LIB= ../lib/libcrypt.a ../lib/libos.a

sscserver:	$(SSCSERVER_OBJ) $(SSCSERVER_LIB)
	$(CC) -o $@ $(SSCSERVER_OBJ) $(SSCSERVER_LIB)

$(BIN)/sscserver: sscserver
	$(INSTALL) sscserver $@

$(ETC_SSC)/services: services.proto
	mkdir -p $(ETC_SSC)
	$(INSTALL) services.proto $@

clean:
	rm -f sscserver $(SSCSERVER_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:24:17 philip Exp $
