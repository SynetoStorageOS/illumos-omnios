#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2014 <contributor>
#

PROG = diskinfo

include ../Makefile.cmd

CPPFLAGS += -I. -I../common -I../../lib/fm/topo/modules/common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE) $(XSTRCONST)
LDLIBS += -L$(ROOT)/usr/lib/fm -ltopo -lnvpair -ldiskmgt
LDFLAGS += -R/usr/lib/fm

all: $(PROG)

install: $(ROOTPROG)

clean:

lint: lint_PROG

include ../Makefile.targ
