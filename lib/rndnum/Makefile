# Makefile for lib/rndnum

#CC=gcc -O9
OBJ=rndnum.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 10:02:25 philip Exp $
