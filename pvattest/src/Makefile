include ../../common.mak

bin_PROGRAM = pvattest
PKGDATADIR ?= "$(DESTDIR)$(TOOLS_DATADIR)/$(bin_PROGRAM)"

SRC_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR = $(rootdir)
PVATTESTDIR := $(ROOT_DIR)/pvattest
INCLUDE_PATHS = "$(SRC_DIR)" "$(ROOT_DIR)/include"
INCLUDE_PARMS = $(addprefix -I,$(INCLUDE_PATHS))

LIBPV_DIR = $(ROOT_DIR)/libpv
LIBPV = $(LIBPV_DIR)/libpv.a

WARNINGS := -Wall -Wextra -Wshadow \
		-Wcast-align -Wwrite-strings -Wmissing-prototypes \
	  	-Wmissing-declarations -Wredundant-decls -Wnested-externs \
		-Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
		-Wpointer-arith -Wno-error=inline \
		-Werror \
		$(NULL)

PVATTEST_SRCS := $(wildcard *.c) \
		$(NULL)

$(bin_PROGRAM)_SRCS := \
		$(PVATTEST_SRCS) \
		$(NULL)

$(bin_PROGRAM)_OBJS := $($(bin_PROGRAM)_SRCS:.c=.o)

ifneq ($(shell sh -c 'command -v pkg-config'),)
GLIB2_CFLAGS := $(shell pkg-config --silence-errors --cflags glib-2.0)
GLIB2_LIBS := $(shell pkg-config --silence-errors --libs glib-2.0)
LIBCRYPTO_CFLAGS := $(shell pkg-config --silence-errors --cflags libcrypto openssl)
LIBCRYPTO_LIBS := $(shell pkg-config --silence-errors --libs libcrypto openssl)
LIBCURL_CFLAGS := $(shell pkg-config --silence-errors --cflags libcurl)
LIBCURL_LIBS := $(shell pkg-config --silence-errors --libs libcurl)
else
GLIB2_CFLAGS := -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
GLIB2_LIBS := -lglib-2.0
LIBCRYPTO_CFLAGS :=
LIBCRYPTO_LIBS := -lcrypto -lssl
LIBCURL_CFLAGS := -I/usr/include/s390x-linux-gnu
LIBCURL_LIBS := -lcurl
endif


ALL_CFLAGS += -std=gnu11 -DPKGDATADIR=$(PKGDATADIR) \
		$(GLIB2_CFLAGS) \
		$(LIBCRYPTO_CFLAGS) \
		$(WARNINGS) \
		$(NULL)
ifeq ("${NO_MEASURE}", "1")
	ALL_CFLAGS += -DPVATTEST_NO_MEASURE
endif

ALL_CPPFLAGS += $(INCLUDE_PARMS)
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)

BUILD_TARGETS := skip-$(bin_PROGRAM)
INSTALL_TARGETS := skip-$(bin_PROGRAM)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
ifneq (${HAVE_LIBCURL}, 0)
BUILD_TARGETS := $(bin_PROGRAM)
INSTALL_TARGETS := install-$(bin_PROGRAM)
endif
endif
endif

all: $(BUILD_TARGETS)

install: $(INSTALL_TARGETS)



$(bin_PROGRAM): $($(bin_PROGRAM)_OBJS) $(LIBPV)

skip-$(bin_PROGRAM):
		echo "  SKIP    $(bin_PROGRAM) due to unresolved dependencies"
prcflags:
	echo $(ALL_CFLAGS)

clean:
	$(RM) -f -- $($(bin_PROGRAM)_OBJS) $(bin_PROGRAM) .check-dep-$(bin_PROGRAM) .detect-openssl.dep.c

install-$(bin_PROGRAM): $(bin_PROGRAM)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -c $^ $(DESTDIR)$(USRBINDIR)


.PHONY: all install clean skip-$(bin_PROGRAM) install-$(bin_PROGRAM)

$($(bin_PROGRAM)_OBJS): .check-dep-$(bin_PROGRAM)

.detect-openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10100000L" >> $@
	echo "  #error openssl version 1.1.0 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check-dep-$(bin_PROGRAM): .detect-openssl.dep.c
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		"glib.h", \
		"glib2-devel / libglib2.0-dev", \
		"HAVE_GLIB2=0")
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		"openssl/evp.h", \
		"openssl-devel / libssl-dev version >= 1.1.0", \
		"HAVE_OPENSSL=0", \
		"-I.")
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0")
	touch $@
