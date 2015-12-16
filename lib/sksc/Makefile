# Makefile for lib/sksc

#CC=gcc -O9
OBJ=sksc.o
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
# $PchId: Makefile,v 1.2 2011/12/27 22:50:57 philip Exp $
