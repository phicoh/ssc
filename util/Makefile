# Makefile for util

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	rsagen ssc_runas tcpmux

install: $(BIN)/rsagen $(BIN)/ssc_runas $(BIN)/tcpmux

RSAGEN_OS=
RSAGEN_OBJ=	rsagen.o $(RSAGEN_OS)
RSAGEN_LIB=	../lib/libcrypt.a ../lib/libos.a

SSC_RUNAS_OS=
SSC_RUNAS_OBJ=	ssc_runas.o $(SSC_RUNAS_OS)
SSC_RUNAS_LIB=	../lib/libos.a

TCPMUX_OS=
TCPMUX_OBJ=	tcpmux.o $(TCPMUX_OS)
TCPMUX_LIB=	../lib/libos.a

rsagen:	$(RSAGEN_OBJ) $(RSAGEN_LIB)
	$(CC) -o $@ $(RSAGEN_OBJ) $(RSAGEN_LIB)

$(BIN)/rsagen: rsagen
	$(INSTALL) rsagen $@

ssc_runas:	$(SSC_RUNAS_OBJ) $(SSC_RUNAS_LIB)
	$(CC) -o $@ $(SSC_RUNAS_OBJ) $(SSC_RUNAS_LIB)

$(BIN)/ssc_runas: ssc_runas
	$(INSTALL) ssc_runas $@

tcpmux:	$(TCPMUX_OBJ) $(TCPMUX_LIB)
	$(CC) -o $@ $(TCPMUX_OBJ) $(TCPMUX_LIB)

$(BIN)/tcpmux: tcpmux
	$(INSTALL) tcpmux $@

clean:
	rm -f ssc_runas $(SSC_RUNAS_OBJ)
	rm -f rsagen $(RSAGEN_OBJ)
	rm -f tcpmux $(TCPMUX_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:19:55 philip Exp $
