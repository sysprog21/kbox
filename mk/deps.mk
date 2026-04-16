# External dependency fetching / building (LKL, minislirp)

# FORCE_LKL_BUILD=1  – clone lkl/linux and build liblkl.a from source.
#                      The source tree is kept in build/lkl-src so
#                      subsequent builds reuse it (pass LKL_DIR= to override).
# (default)          – download prebuilt tarball from the lkl-nightly release.

ifeq ($(FORCE_LKL_BUILD),1)

# Always re-invoke the build script so the sub-make inside it can detect
# source changes and perform an incremental rebuild of liblkl.a.
# The FORCE sentinel (a phony with no recipe) makes Make treat $(LKL_LIB)
# as always out of date, while the sub-make handles the actual incrementality.
.PHONY: _lkl_force
_lkl_force:

$(LKL_LIB): _lkl_force
	@echo "  BUILD   lkl (from source)"
	$(Q)./scripts/build-lkl.sh $(ARCH)

else

# Auto-fetch LKL if missing
$(LKL_LIB):
	@echo "  FETCH   lkl"
	$(Q)./scripts/fetch-lkl.sh $(ARCH)

endif

.PHONY: fetch-lkl
fetch-lkl:
	@echo "  FETCH   lkl"
	$(Q)./scripts/fetch-lkl.sh $(ARCH)

.PHONY: build-lkl
build-lkl:
	@echo "  BUILD   lkl (from source)"
	$(Q)./scripts/build-lkl.sh $(ARCH)

# Auto-fetch minislirp if missing (shallow clone, no submodule).
# $(wildcard) evaluates at parse time, so if minislirp has not been fetched yet
# SLIRP_SRCS is empty. Guard: fetch and re-eval so the wildcard picks up
# the newly-cloned sources.
ifeq ($(CONFIG_HAS_SLIRP),y)
ifneq ($(filter clean distclean config defconfig oldconfig savedefconfig indent,$(MAKECMDGOALS)),)
else
ifeq ($(wildcard $(SLIRP_HDR)),)
$(shell ./scripts/fetch-minislirp.sh >&2)
SLIRP_SRCS = $(shell ls $(SLIRP_DIR)/src/*.c 2>/dev/null)
SLIRP_OBJS = $(SLIRP_SRCS:.c=.o)
endif
endif

.PHONY: fetch-minislirp
fetch-minislirp:
	@echo "  FETCH   minislirp"
	$(Q)scripts/fetch-minislirp.sh
endif

.PHONY: fetch-iperf3
fetch-iperf3:
	@echo "  FETCH   iperf3"
	$(Q)sh scripts/fetch-iperf3.sh $(ARCH)

.PHONY: fetch-netperf
fetch-netperf:
	@echo "  FETCH   netperf"
	$(Q)sh scripts/fetch-netperf.sh


# Generate compiled-in web assets from web/ directory.
# Re-run when any web/ file changes.
ifeq ($(CONFIG_HAS_WEB),y)
WEB_SRCS_ALL = $(wildcard web/*.html web/*.css web/*.js web/*.svg)
$(WEB_ASSET_SRC): $(WEB_SRCS_ALL) scripts/gen-web-assets.sh
	@echo "  GEN     $@"
	$(Q)scripts/gen-web-assets.sh

.PHONY: web-assets
web-assets: $(WEB_ASSET_SRC)
endif
