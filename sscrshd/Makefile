# Makefile for sscrshd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install

all:	sscrshd

install: $(BIN)/sscrshd

#SSCRSHD_OS=	os_minix.o
SSCRSHD_OBJ=	sscrshd.o $(SSCRSHD_OS)
SSCRSHD_LIB=	../lib/libos.a

sscrshd:	$(SSCRSHD_OBJ) $(SSCRSHD_LIB)
	$(CC) -o $@ $(SSCRSHD_OBJ) $(SSCRSHD_LIB)

$(BIN)/sscrshd: sscrshd
	$(INSTALL) sscrshd $@

clean:
	rm -f sscrshd $(SSCRSHD_OBJ)

#
# $PchId: Makefile,v 1.2 2005/06/01 10:14:35 philip Exp $
