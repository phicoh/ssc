# Makefile for ssctelnet

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS} -I../include

all:	ssctelnet

install: $(BIN)/ssctelnet

SSCTELNET_OBJ=	ssctelnet.o ttn_conf.o os.o
SSCTELNET_LIB=	../lib/libos.a

ssctelnet:	$(SSCTELNET_OBJ) $(SSCTELNET_LIB)
	$(CC) -o $@ $(SSCTELNET_OBJ) $(SSCTELNET_LIB)

$(BIN)/ssctelnet: ssctelnet
	$(INSTALL) ssctelnet $@

os.o:	os_minix.c os_posix.c

clean:
	rm -f ssctelnet $(SSCTELNET_OBJ)

#
# $PchId: Makefile,v 1.5 2012/01/27 15:57:47 philip Exp $
