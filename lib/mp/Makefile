# Makefile for lib/prime

#CC=gcc -O9
OBJ=bigmath.o bignum.o bigpow.o coremult.o euclid.o fastmult.o ioutils.o \
	longmult.o memalloc.o msbtable.o
LIBCRYPT=../libcrypt.a
AR=ar

all:	${LIBCRYPT}
	$(ALWAYS_AR) r ${LIBCRYPT} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBCRYPT}:	$(OBJ)
	$(AR) r $@ $(OBJ)

