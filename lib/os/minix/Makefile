# Makefile for lib/os/minix

#CC=gcc -O9
OBJ=random.o strlcat.o strlcpy.o syslog.o
LIBOS=../../libos.a
AR=ar

all:	${LIBOS}
	$(AR) r ${LIBOS} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBOS}:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.2 2011/12/29 20:34:44 philip Exp $
