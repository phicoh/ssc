# Makefile for lib/hmac

#CC=gcc -O9
OBJ=hmac_sha256.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 13:30:51 philip Exp $
