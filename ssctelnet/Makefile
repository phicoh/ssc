# Makefile for ssctelnet

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	ssctelnet

install: $(BIN)/ssctelnet

#SSCTELNET_OS=	os_minix.o
SSCTELNET_OBJ=	ssctelnet.o ttn_conf.o $(SSCTELNET_OS)
#SSCTELNET_LIB=	

ssctelnet:	$(SSCTELNET_OBJ) $(SSCTELNET_LIB)
	$(CC) -o $@ $(SSCTELNET_OBJ) $(SSCTELNET_LIB)

$(BIN)/ssctelnet: ssctelnet
	$(INSTALL) ssctelnet $@

clean:
	rm -f ssctelnet $(SSCTELNET_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:14:59 philip Exp $
