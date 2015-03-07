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

PROG=virtual-storage

OBJS=virtual-storage.o

include ../Makefile.cmd
include ../Makefile.ctf

CPPFLAGS += -I. -I$(ROOT)/usr/include -I../../uts/common/fs/zfs -I../../lib/libdladm/common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE) $(XSTRCONST)
LDLIBS += -L$(ROOT)/usr/lib -lzfs -lsocket -lnsl -lkstat

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: $(ROOTPROG)

clean:

lint: lint_PROG
