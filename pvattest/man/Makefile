include ../../common.mak

all:

man:
ifeq (, $(shell which txt2man 2> /dev/null))
	$(error txt2man not in PATH, cannot generate man pages for pvattest)
endif
	${MAKE} -C ../src pvattest
	./create-man-pages.bash

install: man
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c *.8 -t $(DESTDIR)$(MANDIR)/man8

clean:
	${RM} -f *.8

.PHONY: all install clean
