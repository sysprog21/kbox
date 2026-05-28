# mk/tests.mk - Test targets (unit, integration, stress, guest binaries)

# Unit test files (no LKL dependency)
# Portable tests (compile on any host):
TEST_DIR   = tests/unit
TEST_SRCS  = $(TEST_DIR)/test-runner.c \
             $(TEST_DIR)/test-fd-table.c \
			 $(TEST_DIR)/test-fd-table-refcount.c \
             $(TEST_DIR)/test-path.c \
             $(TEST_DIR)/test-mount.c \
             $(TEST_DIR)/test-cli.c \
             $(TEST_DIR)/test-identity.c \
             $(TEST_DIR)/test-syscall-nr.c \
             $(TEST_DIR)/test-elf.c \
             $(TEST_DIR)/test-x86-decode.c

# Linux-only tests (depend on inline asm, siginfo_t/ucontext, memfd_create):
ifeq ($(shell uname -s),Linux)
TEST_SRCS += $(TEST_DIR)/test-rewrite.c \
             $(TEST_DIR)/test-procmem.c \
             $(TEST_DIR)/test-syscall-request.c \
             $(TEST_DIR)/test-syscall-trap.c \
             $(TEST_DIR)/test-loader-entry.c \
             $(TEST_DIR)/test-loader-handoff.c \
             $(TEST_DIR)/test-loader-image.c \
             $(TEST_DIR)/test-loader-layout.c \
             $(TEST_DIR)/test-loader-launch.c \
             $(TEST_DIR)/test-loader-stack.c \
             $(TEST_DIR)/test-loader-transfer.c
endif

# Unit tests link only the pure-computation sources (no LKL)
TEST_SUPPORT_SRCS = $(SRC_DIR)/fd-table.c \
                    $(SRC_DIR)/path.c \
                    $(SRC_DIR)/mount.c \
                    $(TEST_DIR)/test-mount-stubs.c \
                    $(SRC_DIR)/cli.c \
                    $(SRC_DIR)/identity.c \
                    $(SRC_DIR)/syscall-nr.c \
                    $(SRC_DIR)/elf.c \
                    $(SRC_DIR)/x86-decode.c

ifeq ($(shell uname -s),Linux)
TEST_SUPPORT_SRCS += $(SRC_DIR)/rewrite.c \
                     $(TEST_DIR)/test-seccomp-stubs.c \
                     $(SRC_DIR)/procmem.c \
                     $(SRC_DIR)/syscall-request.c \
                     $(SRC_DIR)/syscall-trap.c \
                     $(SRC_DIR)/loader-entry.c \
                     $(SRC_DIR)/loader-handoff.c \
                     $(SRC_DIR)/loader-image.c \
                     $(SRC_DIR)/loader-layout.c \
                     $(SRC_DIR)/loader-launch.c \
                     $(SRC_DIR)/loader-stack.c \
                     $(SRC_DIR)/loader-transfer.c
endif

TEST_TARGET  = tests/unit/test-runner

# Guest test programs (compiled statically, run inside kbox)
GUEST_DIR    = tests/guest
GUEST_SRCS   = $(wildcard $(GUEST_DIR)/*-test.c)
GUEST_BINS   = $(GUEST_SRCS:.c=)

# Stress test programs (compiled statically, run inside kbox)
STRESS_DIR   = tests/stress
STRESS_SRCS  = $(wildcard $(STRESS_DIR)/*.c)
STRESS_BINS  = $(STRESS_SRCS:.c=)

# Rootfs image
ROOTFS       = alpine.ext4

# ---- Test targets ----

check: check-unit check-integration check-stress

check-unit: $(TEST_TARGET)
	@echo "  RUN     check-unit"
	$(Q)./$(TEST_TARGET)

# Unit tests are built WITHOUT linking LKL.
# We define LKL stubs for functions referenced by test support code.
TEST_LDFLAGS = $(filter-out -L$(LKL_DIR) -L$(LKL_DIR)/lib,$(LDFLAGS))

$(TEST_TARGET): $(TEST_SRCS) $(TEST_SUPPORT_SRCS) $(wildcard .config)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -DKBOX_UNIT_TEST -o $@ $(TEST_SRCS) $(TEST_SUPPORT_SRCS) $(TEST_LDFLAGS) -lpthread

check-integration: $(TARGET) guest-bins stress-bins $(ROOTFS)
	@echo "  RUN     check-integration"
	$(Q)./scripts/run-tests.sh ./$(TARGET) $(ROOTFS)

check-stress: $(TARGET) stress-bins $(ROOTFS)
	@echo "  RUN     check-stress"
	$(Q)./scripts/run-stress.sh ./$(TARGET) $(ROOTFS)

# ---- Guest / stress binaries (static, no ASAN) ----
# These are cross-compiled on Linux and placed into the rootfs.
# They must be statically linked and cannot use sanitizers.

guest-bins: $(GUEST_BINS)

$(GUEST_DIR)/%-test: $(GUEST_DIR)/%-test.c
	@echo "  CC      $<"
	$(Q)$(CC) -std=gnu11 -Wall -Wextra -O2 -static -o $@ $<

stress-bins: $(STRESS_BINS)

$(STRESS_DIR)/%: $(STRESS_DIR)/%.c
	@echo "  CC      $<"
	$(Q)$(CC) -std=gnu11 -Wall -Wextra -O2 -static -pthread -o $@ $<

# ---- Rootfs ----

rootfs: $(ROOTFS)

$(ROOTFS): scripts/mkrootfs.sh scripts/alpine-sha256.txt $(GUEST_BINS) $(STRESS_BINS)
	@echo "  GEN     $@"
	$(Q)ALPINE_ARCH=$(ARCH) ./scripts/mkrootfs.sh

# ---- Syntax-only compilation check (used by pre-commit hook) ----
# Usage: make check-syntax CHK_SOURCES="src/foo.c src/bar.c"
# Uses the project's real CFLAGS with -fsyntax-only (no linking, no .o output).
# Skips gracefully on non-Linux compilers.

CHK_CC_TARGET := $(shell $(CC) -dumpmachine 2>/dev/null)
check-syntax:
ifeq ($(findstring linux,$(CHK_CC_TARGET)),)
	@echo "  SKIP    check-syntax (non-Linux compiler: $(CHK_CC_TARGET))"
else
ifdef CHK_SOURCES
	@echo "  SYNTAX  $(words $(CHK_SOURCES)) file(s)"
	$(Q)$(CC) $(CFLAGS) -DKBOX_UNIT_TEST -fsyntax-only \
	    -Werror=implicit-function-declaration \
	    -Werror=incompatible-pointer-types \
	    -Werror=int-conversion \
	    -Werror=return-type \
	    -Werror=format=2 \
	    -Werror=format-security \
	    -Werror=strict-prototypes \
	    -Werror=old-style-definition \
	    -Werror=sizeof-pointer-memaccess \
	    -Werror=vla \
	    $(CHK_SOURCES)
else
	@echo "  SYNTAX  all source files"
	$(Q)$(CC) $(CFLAGS) -DKBOX_UNIT_TEST -fsyntax-only \
	    -Werror=implicit-function-declaration \
	    -Werror=incompatible-pointer-types \
	    -Werror=int-conversion \
	    -Werror=return-type \
	    -Werror=format=2 \
	    -Werror=format-security \
	    -Werror=strict-prototypes \
	    -Werror=old-style-definition \
	    -Werror=sizeof-pointer-memaccess \
	    -Werror=vla \
	    $(SRCS)
endif
endif

# ---- Commit-log validation (Change-Id, subject format) ----
check-commitlog:
	@echo "  RUN     check-commitlog"
	$(Q)scripts/check-commitlog.sh

.PHONY: check check-unit check-integration check-stress check-commitlog guest-bins stress-bins rootfs check-syntax
