# Makefile for util

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

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
	$(CC) -o $@ $(LDFLAGS) $(RSAGEN_OBJ) $(RSAGEN_LIB)

$(BIN)/rsagen: rsagen
	$(INSTALL) rsagen $@

ssc_runas:	$(SSC_RUNAS_OBJ) $(SSC_RUNAS_LIB)
	$(CC) -o $@ $(LDFLAGS) $(SSC_RUNAS_OBJ) $(SSC_RUNAS_LIB)

$(BIN)/ssc_runas: ssc_runas
	$(INSTALL) ssc_runas $@

tcpmux:	$(TCPMUX_OBJ) $(TCPMUX_LIB)
	$(CC) -o $@ $(LDFLAGS) $(TCPMUX_OBJ) $(TCPMUX_LIB)

$(BIN)/tcpmux: tcpmux
	$(INSTALL) tcpmux $@

clean:
	rm -f ssc_runas $(SSC_RUNAS_OBJ)
	rm -f rsagen $(RSAGEN_OBJ)
	rm -f tcpmux $(TCPMUX_OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 11:45:40 philip Exp $
