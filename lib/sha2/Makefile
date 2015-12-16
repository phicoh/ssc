# Makefile for lib/sha2

#CC=gcc -O9
OBJ=sha2.o
LIBCRYPT=../libcrypt.a
AR=ar
CFLAGS=${ARCH_FLAGS} -I../../include

all:	${LIBCRYPT}
	$(AR) r ${LIBCRYPT} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBCRYPT}:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/27 22:48:42 philip Exp $
