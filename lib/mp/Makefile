# Makefile for lib/prime

#CC=gcc -O9
OBJ=bigmath.o bignum.o bigpow.o coremult.o euclid.o fastmult.o ioutils.o \
	longmult.o memalloc.o msbtable.o
AR=ar

all:	../libcrypt.a

clean:
	rm -f $(OBJ)

../libcrypt.a:	$(OBJ)
	$(AR) r $@ $(OBJ)
