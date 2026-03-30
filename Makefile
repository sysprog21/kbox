# Build:  make [BUILD=release]
# Config: make config       (interactive menuconfig)
#         make defconfig    (all features enabled)
# Test:   make check

.DEFAULT_GOAL := all

# Kconfig integration

KCONFIG_DIR  := tools/kconfig
KCONFIG_CONF := configs/Kconfig

# Load configuration (safe include -- no error if .config is absent)
-include .config

# Targets that don't require .config
CONFIG_TARGETS    := config defconfig oldconfig savedefconfig clean distclean indent \
                     check-unit check-syntax check-commitlog fetch-lkl build-lkl \
                     fetch-minislirp install-hooks guest-bins stress-bins rootfs
CONFIG_GENERATORS := config defconfig oldconfig

# Require .config for build targets.
# Note: 'make defconfig && make' is the correct two-step sequence.
# 'make defconfig all' does NOT work because .config is parsed at
# Make startup, before any recipe runs.
BUILD_GOALS    := $(filter-out $(CONFIG_TARGETS),$(or $(MAKECMDGOALS),all))
HAS_CONFIG_GEN := $(filter $(CONFIG_GENERATORS),$(MAKECMDGOALS))
ifneq ($(BUILD_GOALS),)
ifeq ($(HAS_CONFIG_GEN),)
ifeq ($(wildcard .config),)
    $(info )
    $(info *** Configuration file ".config" not found!)
    $(info *** Please run 'make config' or 'make defconfig' first.)
    $(info )
    $(error Configuration required)
endif
endif
endif

# Include modular build fragments
include mk/toolchain.mk
include mk/features.mk
include mk/deps.mk
include mk/tests.mk
include mk/format.mk

# Top-level targets
.PHONY: all clean distclean config defconfig oldconfig savedefconfig install-hooks

all: $(TARGET)
ifneq ($(wildcard .git/hooks),)
all: | .git/hooks/pre-commit
endif

$(TARGET): $(OBJS) $(LKL_LIB)
	@echo "  LD      $@"
	$(Q)$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

# Rebuild all objects when .config changes (CFLAGS may differ).
$(OBJS): $(wildcard .config)

%.o: %.c
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Auto-install git hooks on first build (skipped in worktrees where .git is a file).
.git/hooks/pre-commit: scripts/pre-commit.hook
	$(Q)if [ -d .git/hooks ]; then $(MAKE) install-hooks; fi

install-hooks:
	$(Q)for hook in scripts/*.hook; do \
	    name=$$(basename "$$hook" .hook); \
	    if [ ! -e .git/hooks/"$$name" ] && [ ! -L .git/hooks/"$$name" ]; then \
	        ln -s ../../"$$hook" .git/hooks/"$$name"; \
	        echo "Installed $$name hook"; \
	    fi; \
	done

# Kconfig targets

# Fetch Kconfiglib on demand, then run the appropriate tool.
config: | $(KCONFIG_DIR)/menuconfig.py
	$(Q)KCONFIG_CONFIG=.config python3 $(KCONFIG_DIR)/menuconfig.py $(KCONFIG_CONF)
	@echo "  CONFIG  .config"

defconfig: | $(KCONFIG_DIR)/menuconfig.py
	@echo "  CONFIG  defconfig"
	$(Q)KCONFIG_CONFIG=.config python3 $(KCONFIG_DIR)/defconfig.py --kconfig $(KCONFIG_CONF) configs/defconfig

oldconfig: | $(KCONFIG_DIR)/menuconfig.py
	@echo "  CONFIG  oldconfig"
	$(Q)KCONFIG_CONFIG=.config python3 $(KCONFIG_DIR)/oldconfig.py $(KCONFIG_CONF)

savedefconfig: | $(KCONFIG_DIR)/menuconfig.py
	@echo "  CONFIG  savedefconfig"
	$(Q)KCONFIG_CONFIG=.config python3 $(KCONFIG_DIR)/savedefconfig.py --kconfig $(KCONFIG_CONF) --out configs/defconfig

$(KCONFIG_DIR)/menuconfig.py:
	@echo "  FETCH   kconfiglib"
	$(Q)scripts/fetch-kconfiglib.sh

# Clean

clean:
	@echo "  CLEAN"
	$(Q)rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET) $(TEST_TARGET) $(TEST_DIR)/*.o
	$(Q)rm -f src/*.o src/*.d src/web-assets.c
	$(Q)rm -f $(GUEST_BINS) $(STRESS_BINS)

distclean: clean
	@echo "  CLEAN   distclean"
	$(Q)rm -f .config .config.old
	$(Q)rm -rf $(KCONFIG_DIR)

# Auto-generated header dependencies (-MMD -MP writes .d alongside .o)
-include $(OBJS:.o=.d)
