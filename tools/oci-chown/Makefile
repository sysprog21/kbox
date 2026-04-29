# SPDX-License-Identifier: MIT
# Standalone build for oci-chown. Not part of the kbox supervisor build.
# Linked against libext2fs from e2fsprogs. Run from this directory or via
# `make -C tools/oci-chown`.

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -std=gnu11
CPPFLAGS ?=
LDFLAGS  ?=
# error_message() comes from libcom_err (com_err is e2fsprogs's error tables).
LDLIBS   := -lext2fs -lcom_err

# pkg-config covers both ext2fs and com_err on most distros. Treat the
# discovered include paths as preprocessor flags (CPPFLAGS) and the link
# fragments as LDLIBS, so callers can still augment CFLAGS/LDFLAGS from
# the environment without losing the pkg-config-discovered paths.
PKG_CFLAGS := $(shell pkg-config --cflags ext2fs com_err 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs   ext2fs com_err 2>/dev/null)

ifneq ($(PKG_CFLAGS),)
CPPFLAGS += $(PKG_CFLAGS)
endif
ifneq ($(PKG_LIBS),)
LDLIBS := $(PKG_LIBS)
endif

TARGET := oci-chown

$(TARGET): oci-chown.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean
