# Makefile for sscrsh

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

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
# $PchId: Makefile,v 1.2 2005/06/01 10:14:05 philip Exp $
