# mk/toolchain.mk - Compiler detection and Kconfig-derived flags

CC       ?= gcc
CFLAGS   ?=
LDFLAGS  ?=

ARCH ?= $(shell uname -m)

# Verbosity: silent by default, 'make V=1' shows full commands.
ifeq ($(V),1)
  Q :=
else
  Q := @
  MAKEFLAGS += --no-print-directory
endif

# kbox is Linux-only. Bail if the compiler does not target Linux.
# Skip the check for targets that don't compile (config, clean, indent, etc.).
ifneq ($(BUILD_GOALS),)
CC_TARGET := $(shell $(CC) -dumpmachine 2>/dev/null)
ifeq ($(findstring linux,$(CC_TARGET)),)
  $(error $(CC) targets '$(CC_TARGET)', not Linux. kbox requires a Linux-targeting compiler)
endif
endif

# Base C flags (always applied)
CFLAGS  += -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow
CFLAGS  += -Wno-unused-parameter
CFLAGS  += -Iinclude -Isrc
LDFLAGS += -Wl,-z,noexecstack -Wl,-z,separate-code

# Build mode from Kconfig (fallback to BUILD= for unconfigured builds)
ifeq ($(CONFIG_BUILD_RELEASE),y)
  CFLAGS  += -O2 -DNDEBUG
else ifeq ($(BUILD),release)
  CFLAGS  += -O2 -DNDEBUG
else
  CFLAGS  += -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

# LKL library location (from Kconfig or command line)
ifdef CONFIG_LKL_DIR
  LKL_DIR := $(patsubst "%",%,$(CONFIG_LKL_DIR))
endif
ifeq ($(strip $(LKL_DIR)),)
  LKL_DIR := lkl-$(ARCH)
endif

LKL_LIB   = $(LKL_DIR)/liblkl.a

LDFLAGS += -L$(LKL_DIR) -L$(LKL_DIR)/lib
LDLIBS   = -llkl -lpthread -ldl -lm -lrt
