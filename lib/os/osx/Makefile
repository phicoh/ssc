# Makefile for lib/os/solaris

#CC=gcc -O9
OBJ=random.o
LIBOS=../../libos.a
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	${LIBOS}
	$(ALWAYS_AR) r ${LIBOS} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBOS}:	$(OBJ)
	$(AR) r $@ $(OBJ)

random.o: ../linux/random.c
	$(CC) $(CFLAGS) -c ../linux/random.c

#
# $PchId: Makefile,v 1.1 2011/12/28 12:13:45 philip Exp $
