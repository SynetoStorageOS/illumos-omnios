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
# Copyright (C) 2015 Syneto LTD.
#

PROG = diskinfo

OBJS=diskinfo.o diskname_converter.o kstats.o

include ../Makefile.cmd
include ../Makefile.ctf

CPPFLAGS += -I. -I$(ROOT)/usr/include -I../stat/common -I../../lib/fm/topo/modules/common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE) $(XSTRCONST) -I${STATCOMMONDIR}
LDLIBS += -L$(ROOT)/usr/lib/fm -L$(ROOT)/usr/lib -ltopo -lnvpair -ldiskmgt -lkstat -lavl -ldevinfo -lcfgadm
LDFLAGS=-R/usr/lib/fm

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:

lint: lint_PROG

include ../Makefile.targ
