# Makefile for lib/rsa

#CC=gcc -O9
OBJ=rsa.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/02 15:12:22 philip Exp $
