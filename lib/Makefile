# Makefile for lib

ALWAYS_AR=:

SUBDIRS=cbcmac dh hmac misc mp ${ARCH_SUBDIR} prime prnd rndnum rijndael rsa \
	sha2 sksc
all:	subdirs

install: all

subdirs:
	set -e; for i in $(SUBDIRS); do \
		(echo $$i:; cd $$i && $(MAKE) ARCH_FLAGS="${ARCH_FLAGS}" \
		ALWAYS_AR="${ALWAYS_AR}" all); \
	done

clean:
	rm -f libcrypt.a
	rm -f libos.a
	for i in $(SUBDIRS); do (echo $$i:; cd $$i && make clean); done


#
# $PchId: Makefile,v 1.3 2011/12/27 22:23:04 philip Exp $
