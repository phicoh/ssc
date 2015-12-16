# Makefile for sscserver

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

ETC_SSC=/etc/ssc

all:	sscserver

install: $(BIN)/sscserver $(ETC_SSC)/services

SSCSERVER_OS=	os.o
SSCSERVER_OBJ=	auth.o dh.o rsa.o service.o sscserver.o $(SSCSERVER_OS)
SSCSERVER_LIB= ../lib/libcrypt.a ../lib/libos.a

sscserver:	$(SSCSERVER_OBJ) $(SSCSERVER_LIB)
	$(CC) -o $@ $(LDFLAGS) $(SSCSERVER_OBJ) $(SSCSERVER_LIB) $(OS_LIBS)

$(BIN)/sscserver: sscserver
	$(INSTALL) sscserver $@

$(ETC_SSC)/services: services.proto
	mkdir -p $(ETC_SSC)
	$(INSTALL) services.proto $@

os.o:	os_minix.c
os.o:	os_linux.c

clean:
	rm -f sscserver $(SSCSERVER_OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 11:58:30 philip Exp $
