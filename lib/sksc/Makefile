# Makefile for lib/sksc

#CC=gcc -O9
OBJ=sksc.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/06 19:33:05 philip Exp $
