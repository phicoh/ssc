# Makefile for sscrsh

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

all:	sscrsh

install: $(BIN)/sscrsh

#SSCRSH_OS=	os_minix.o
SSCRSH_OBJ=	sscrsh.o $(SSCRSH_OS)
SSCRSH_LIB=	../lib/libcrypt.a ../lib/libos.a

sscrsh:	$(SSCRSH_OBJ) $(SSCRSH_LIB)
	$(CC) -o $@ $(SSCRSH_OBJ) $(SSCRSH_LIB)

$(BIN)/sscrsh:	sscrsh
	$(INSTALL) sscrsh $@

clean:
	rm -f sscrsh $(SSCRSH_OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 11:53:28 philip Exp $
