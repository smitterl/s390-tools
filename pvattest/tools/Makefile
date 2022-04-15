include ../../common.mak

# List of test programs
TESTS_C := exchange_info
TEST_TARGETS := $(TESTS_C)

ROOT_DIR = $(rootdir)
PVATTEST_DIR :=$(ROOT_DIR)/pvattest/src
LIBPV_INCLUDE_DIR := $(ROOT_DIR)/include

INCLUDE_PATHS = "$(CURDIR)" "$(PVATTEST_DIR)" "$(LIBPV_INCLUDE_DIR)"
INCLUDE_PARMS = $(addprefix -I,$(INCLUDE_PATHS))

WARNINGS := -Wall -Wextra -Wshadow \
	-Wcast-align -Wwrite-strings -Wmissing-prototypes		   \
	-Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline \
	-Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
	-Wno-pointer-arith \
	-Wno-unused-function -Wno-unused-parameter -Wno-unused-variable \
	-Werror \
	$(NULL)

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
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)

ALL_CFLAGS += -std=gnu11 \
	-Dabs_testdir=\"$(CURDIR)\" \
	$(GLIB2_CFLAGS) $(LIBCRYPTO_CFLAGS) \
	$(WARNINGS) \
	$(NULL)
ALL_CPPFLAGS += $(INCLUDE_PARMS)

LIBPV_DIR = $(ROOT_DIR)/libpv
LIBPV := $(LIBPV_DIR)/libpv.a

PVATTEST_SRCS := $(filter-out %/pvattest.c,$(wildcard $(PVATTEST_DIR)/*.c))
PVATTEST_OBJS := $(patsubst %.c,%.o,$(PVATTEST_SRCS))

define make-target
$(1): $($(1)_SOURCES:.c=.o) $(1).o $(PVATTEST_OBJS) $(LIBPV)
	$(LINK) $(ALL_LDFLAGS) $($(1)_LDFLAGS) $$^ $(LDLIBS) $($(1)_LDADD) -o $$@
  $(1).o: $(1).c
		$(CC) $(ALL_CPPFLAGS) $($(1)_CPPFLAGS) $(ALL_CFLAGS) $($(1)_CFLAGS) -c $$< -o $$@
endef

install:
	echo ignore 2>1 >/dev/null

$(foreach element,$(TESTS_C),$(eval $(call make-target,$(element))))

clean:
	-$(RM) -f *.o $(TESTS_C)

.PHONY: clean

# .FORCE:
# ../../%.o: .FORCE
# 	$(MAKE) --directory $(PVATTEST_DIR) $(@:../../%=%)
