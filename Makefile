#
# Written by Alexey Vatchenko <av@bsdua.org>.
# Public domain.
#
PREFIX?=	/usr/local
BINDIR= 	${PREFIX}/libexec
MANDIR= 	${PREFIX}/man/man

PROG=		hotplug-diskmount
SRCS=		hotplug-diskmount.c
MAN=		hotplug-diskmount.8

CFLAGS?= -W -Wall -g -O0

maninstall:
	makewhatis $(PREFIX)/man

uninstall:
	rm $(DESTDIR)$(BINDIR)/$(PROG)
	rm $(DESTDIR)$(MANDIR)8/$(MAN)
	makewhatis $(PREFIX)/man

.include <bsd.prog.mk>
