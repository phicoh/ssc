# Makefile for lib/cbcmac

#CC=gcc -O9
OBJ=cbcmac_aes.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 13:38:48 philip Exp $
