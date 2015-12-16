# Makefile for lib/rsa

#CC=gcc -O9
OBJ=rsa.o
AR=ar
LIBCRYPT=../libcrypt.a
CFLAGS=${ARCH_FLAGS}

all:	${LIBCRYPT}
	$(ALWAYS_AR) r ${LIBCRYPT} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBCRYPT}:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/27 22:45:43 philip Exp $
