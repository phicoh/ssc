# Makefile for sscrshd

#CC=gcc -O9
BIN=/usr/local/bin
INSTALL=install
CFLAGS=${ARCH_FLAGS}

all:	sscrshd

install: $(BIN)/sscrshd

#SSCRSHD_OS=	os_minix.o
SSCRSHD_OBJ=	sscrshd.o $(SSCRSHD_OS)
SSCRSHD_LIB=	../lib/libos.a

sscrshd:	$(SSCRSHD_OBJ) $(SSCRSHD_LIB)
	$(CC) -o $@ $(LDFLAGS) $(SSCRSHD_OBJ) $(SSCRSHD_LIB)

$(BIN)/sscrshd: sscrshd
	$(INSTALL) sscrshd $@

clean:
	rm -f sscrshd $(SSCRSHD_OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 11:49:18 philip Exp $
