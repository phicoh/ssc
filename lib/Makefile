# Makefile for lib

SUBDIRS=cbcmac dh hmac misc mp os/minix prime prnd rndnum rijndael rsa \
	sha2 sksc
all:	subdirs

install: all

subdirs:
	set -e; for i in $(SUBDIRS); do (echo $$i:; cd $$i && make all); done

clean:
	rm -f libcrypt.a
	rm -f libos.a
	for i in $(SUBDIRS); do (echo $$i:; cd $$i && make clean); done


#
# $PchId: Makefile,v 1.2 2005/06/01 10:18:36 philip Exp $
