# Makefile for lib/prnd

#CC=gcc -O9
OBJ=prnd.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 10:55:59 philip Exp $
