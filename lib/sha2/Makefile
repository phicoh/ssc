# Makefile for lib/sha2

#CC=gcc -O9
OBJ=sha2.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/06 20:50:25 philip Exp $
