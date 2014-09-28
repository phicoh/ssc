# Makefile for lib/os/minix

#CC=gcc -O9
OBJ=random.o strlcat.o strlcpy.o syslog.o
AR=ar

all:	../../libos.a

clean:
	rm -f $(OBJ)

../../libos.a:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.1 2005/05/03 12:10:21 philip Exp $
