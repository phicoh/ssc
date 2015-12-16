OBJ=rijndael_alg.o rijndael_api.o
AR=ar
LIBCRYPT=../libcrypt.a

all:	${LIBCRYPT}
	$(ALWAYS_AR) r ${LIBCRYPT} $(OBJ)

clean:
	rm -f $(OBJ)

${LIBCRYPT}:	$(OBJ)
	$(AR) r $@ $(OBJ)

#
# $PchId: Makefile,v 1.3 2011/12/28 12:20:20 philip Exp $
