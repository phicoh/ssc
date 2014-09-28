# Makefile for lib/prime

#CC=gcc -O9
OBJ=isprime.o rndprime.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 10:35:40 philip Exp $
