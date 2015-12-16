# Makefile for lib/misc

#CC=gcc -O9
OBJ=alloc.o
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	../libos.a

clean:
	rm -f $(OBJ)

../libos.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/28 11:46:37 philip Exp $
