# Makefile for lib/rndnum

#CC=gcc -O9
OBJ=rndnum.o
LIBCRYPT=../libcrypt.a
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	${LIBCRYPT}
	$(ALWAYS_AR) r ${LIBCRYPT} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBCRYPT}:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/27 22:44:52 philip Exp $
