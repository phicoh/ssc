# Makefile for lib/os/solaris

#CC=gcc -O9
OBJ=random.o #strlcat.o strlcpy.o
AR=ar
CFLAGS=${ARCH_FLAGS}

all:	../../libos.a

clean:
	rm -f $(OBJ)

../../libos.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

random.o: ../linux/random.c
	$(CC) $(CFLAGS) -c ../linux/random.c

strlcat.o: ../minix/strlcat.c
	$(CC) $(CFLAGS) -c ../minix/strlcat.c

strlcpy.o: ../minix/strlcpy.c
	$(CC) $(CFLAGS) -c ../minix/strlcpy.c

#
# $PchId: Makefile,v 1.1 2011/12/28 12:12:30 philip Exp $
