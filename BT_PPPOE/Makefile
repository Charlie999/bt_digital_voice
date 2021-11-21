PREFIX=/usr
BINDIR=$(PREFIX)/bin

CFLAGS=-Ofast -I..

CC=gcc
INSTALL=ginstall

all:	bt_pppoe
distclean:	clean

clean:
	rm bt_pppoe


#install: all
#	$(INSTALL) -D bt_pppoe $(DESTDIR)$(BINDIR)/bt_pppoe

macmask:
	$(CC) bt_pppoe.c -o bt_pppoe $(CFLAGS)
