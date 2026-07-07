# Feature-conditional source files and flags

SRC_DIR  = src

# Core sources (always built).
# net-slirp.c, web-*.c have #ifdef guards and compile to empty TUs when their
# feature is disabled -- no need to exclude them.
SRCS     = $(SRC_DIR)/main.c \
           $(SRC_DIR)/cli.c \
           $(SRC_DIR)/syscall-nr.c \
           $(SRC_DIR)/lkl-wrap.c \
           $(SRC_DIR)/fd-table.c \
           $(SRC_DIR)/procmem.c \
           $(SRC_DIR)/syscall-request.c \
           $(SRC_DIR)/syscall-trap.c \
           $(SRC_DIR)/path.c \
           $(SRC_DIR)/identity.c \
           $(SRC_DIR)/elf.c \
           $(SRC_DIR)/loader-entry.c \
           $(SRC_DIR)/loader-handoff.c \
           $(SRC_DIR)/loader-image.c \
           $(SRC_DIR)/loader-layout.c \
           $(SRC_DIR)/loader-launch.c \
           $(SRC_DIR)/loader-stack.c \
           $(SRC_DIR)/loader-transfer.c \
           $(SRC_DIR)/x86-decode.c \
           $(SRC_DIR)/rewrite.c \
           $(SRC_DIR)/mount.c \
           $(SRC_DIR)/probe.c \
           $(SRC_DIR)/image.c \
           $(SRC_DIR)/ftrace.c \
           $(SRC_DIR)/seccomp-bpf.c \
           $(SRC_DIR)/seccomp-notify.c \
           $(SRC_DIR)/shadow-fd.c \
           $(SRC_DIR)/seccomp-dispatch.c \
           $(SRC_DIR)/dispatch-net.c \
           $(SRC_DIR)/dispatch-id.c \
           $(SRC_DIR)/dispatch-exec.c \
           $(SRC_DIR)/dispatch-misc.c \
           $(SRC_DIR)/seccomp-supervisor.c \
           $(SRC_DIR)/net-slirp.c \
           $(SRC_DIR)/web-telemetry.c \
           $(SRC_DIR)/web-events.c \
           $(SRC_DIR)/web-server.c

# SLIRP networking
ifeq ($(CONFIG_HAS_SLIRP),y)
  SLIRP_DIR  = externals/minislirp
  SLIRP_HDR  = $(SLIRP_DIR)/src/libslirp.h
  CFLAGS    += -DKBOX_HAS_SLIRP -I$(SLIRP_DIR)/src
  SLIRP_SRCS = $(wildcard $(SLIRP_DIR)/src/*.c)
  SLIRP_OBJS = $(SLIRP_SRCS:.c=.o)
  SLIRP_CFLAGS = $(filter-out -Wpedantic -Wshadow,$(CFLAGS))
  SLIRP_CFLAGS += -Wno-sign-compare -Wno-unused-variable -Wno-comment
  SLIRP_CFLAGS += -Wno-return-type -Wno-pedantic
  SRCS      += $(SLIRP_SRCS)
  # Use a directory-specific pattern rule instead of target-specific CFLAGS.
  # $(SLIRP_OBJS): CFLAGS := ... would expand SLIRP_OBJS at parse time,
  # before deps.mk has cloned minislirp, producing an empty target list.
  $(SLIRP_DIR)/src/%.o: $(SLIRP_DIR)/src/%.c
	@echo "  CC      $<"
	$(Q)$(CC) $(SLIRP_CFLAGS) -MMD -MP -c -o $@ $<
endif

# Web observatory
ifeq ($(CONFIG_HAS_WEB),y)
  CFLAGS       += -DKBOX_HAS_WEB
  WEB_ASSET_SRC = $(SRC_DIR)/web-assets.c
  SRCS         += $(WEB_ASSET_SRC)
endif

# Syscall fast-path (from Kconfig SYSCALL_FAST_PATH)
ifeq ($(CONFIG_SYSCALL_FAST_PATH),y)
  CFLAGS += -DKBOX_AUTO_FAST_PATH=1
else
  CFLAGS += -DKBOX_AUTO_FAST_PATH=0
endif
ifdef CONFIG_STAT_CACHE_SIZE
  CFLAGS += -DKBOX_STAT_CACHE_SIZE=$(patsubst "%",%,$(CONFIG_STAT_CACHE_SIZE))
endif

OBJS     = $(SRCS:.c=.o)
TARGET   = kbox
