# Makefile for lib/cbcmac

#CC=gcc -O9
OBJ=cbcmac_aes.o
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/28 11:47:04 philip Exp $
