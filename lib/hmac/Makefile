# Makefile for lib/hmac

#CC=gcc -O9
OBJ=hmac_sha256.o
AR=ar
CFLAGS=${ARCH_FLAGS} -I../../include

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/27 22:24:25 philip Exp $
