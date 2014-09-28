# Makefile for the Simple Secure Channel implementation (and related utilities)

SUBDIRS=lib sscclient sscserver sscrcp sscrcpd sscrsh sscrshd \
	ssctelnet ssctelnetd util
all:	subdirs

install:
	set -e; for i in $(SUBDIRS); do (echo $$i:; cd $$i && make install); done

subdirs:
	set -e; for i in $(SUBDIRS); do (echo $$i:; cd $$i && make all); done

clean:
	for i in $(SUBDIRS); do (echo $$i:; cd $$i && make clean); done

#
# $PchId: Makefile,v 1.2 2005/06/01 10:21:39 philip Exp $
