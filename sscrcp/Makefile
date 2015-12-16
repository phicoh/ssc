# Makefile for sscrcp

#CC=gcc -O9
INSTALL=install
BIN=/usr/local/bin
CFLAGS=${ARCH_FLAGS}

all:	sscrcp

install: $(BIN)/sscrcp

#SSCRCP_OS=	os_minix.o
SSCRCP_OBJ=	sscrcp.o match.o $(SSCRCP_OS)
SSCRCP_LIB=	../lib/libcrypt.a ../lib/libos.a

sscrcp:	$(SSCRCP_OBJ) $(SSCRCP_LIB)
	$(CC) -o $@ $(SSCRCP_OBJ) $(SSCRCP_LIB)

$(BIN)/sscrcp: sscrcp
	$(INSTALL) sscrcp $@

clean:
	rm -f sscrcp $(SSCRCP_OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 11:48:10 philip Exp $
