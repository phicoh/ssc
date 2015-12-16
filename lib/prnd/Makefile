# Makefile for lib/prnd

#CC=gcc -O9
OBJ=prnd.o
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	$(OBJ)
	$(AR) r ../libcrypt.a $(OBJ)

clean:
	rm -f $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/27 22:43:14 philip Exp $
