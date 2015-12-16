# Makefile for lib/os/linux

#CC=gcc -O9
OBJ=strlcat.o strlcpy.o random.o
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	../../libos.a

clean:
	rm -f $(OBJ)

../../libos.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

strlcat.o: ../minix/strlcat.c
	$(CC) $(CFLAGS) -c ../minix/strlcat.c

strlcpy.o: ../minix/strlcpy.c
	$(CC) $(CFLAGS) -c ../minix/strlcpy.c

#
# $PchId: Makefile,v 1.1 2011/12/28 12:10:27 philip Exp $
