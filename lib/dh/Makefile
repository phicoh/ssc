# Makefile for lib/dh

#CC=gcc -O9
OBJ=dh.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/02 14:04:55 philip Exp $
