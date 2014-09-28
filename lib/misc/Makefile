# Makefile for lib/misc

#CC=gcc -O9
OBJ=alloc.o
AR=ar

all:	../libos.a

clean:
	rm -f $(OBJ)

../libos.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 14:56:22 philip Exp $
