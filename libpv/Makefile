# Common definitions
include ../common.mak

.DEFAULT_GOAL := all

TESTS := tests/
SUBDIRS := src
RECURSIVE_TARGETS := all-recursive install-recursive clean-recursive
LIB := libpv.a

all: ${LIB}

${LIB}: all-recursive
	cp src/${LIB} ${LIB}

install: all install-recursive

clean: clean-recursive
	rm -f -- ${LIB}

$(RECURSIVE_TARGETS):
	@target=`echo $@ |sed s/-recursive//`; \
		for d in $(SUBDIRS); do \
			$(MAKE) -C $$d $$target || exit 1; \
		done

.PHONY: all install clean $(RECURSIVE_TARGETS)
