# Common definitions
include ../common.mak

bin_PROGRAM = pvattest
.DEFAULT_GOAL := $(bin_PROGRAM)

PKGDATADIR := "$(DESTDIR)$(TOOLS_DATADIR)/pvattest"
TESTS :=
SUBDIRS := src man tools
RECURSIVE_TARGETS := all-recursive clean-recursive install-recursive

$(bin_PROGRAM): all

all: all-recursive

install: all install-recursive

clean: clean-recursive

$(RECURSIVE_TARGETS):
	@target=`echo $@ |sed s/-recursive//`; \
		for d in $(SUBDIRS); do \
			$(MAKE) -C $$d $$target || exit 1; \
		done

.PHONY: all install clean $(RECURSIVE_TARGETS) $(bin_PROGRAM)
