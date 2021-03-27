#
# Written by Alexey Vatchenko <av@bsdua.org>.
# Public domain.
#
PROG=	hotplug-diskmount
SRCS=	hotplug-diskmount.c
MAN=	hotplug-diskmount.8
CFLAGS?= -W -Wall -g -O0

BINDIR=/usr/local/libexec

.include <bsd.prog.mk>
