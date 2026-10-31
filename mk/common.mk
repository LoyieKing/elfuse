# mk/common.mk -- Generic build rules
#
# Per-file compilation with automatic dependency tracking, verbosity
# control, and kernel-style build output.  Inspired by libiui's build
# infrastructure.

# Verbosity: make V=1 shows full commands
ifeq ($(V),1)
    Q :=
else
    Q := @
    MAKEFLAGS += --no-print-directory
endif

$(BUILD_DIR):
	@mkdir -p $@

# Automatic header dependency generation (-MMD -MP)
DEPFLAGS = -MMD -MP -MF $(BUILD_DIR)/$(subst /,_,$*).d

# Git hooks, installed on the first make of a fresh clone.
#
# The hooks run the same checks CI does, at commit and push time instead of
# after. Left to "make install-hooks" they are enforced on whoever read the
# README carefully, which is not the population that needs them; the cost of
# being wrong is a symlink, and uninstall-hooks removes it.
#
# Once per tree, not once per build: the stamp is what keeps a rebuild from
# re-running this, and a hook removed by hand stays removed until the next
# clean. A target rather than a read-time side effect, so a dry run or a query
# leaves the checkout untouched. A tarball export has no git dir, which the
# script exits 0 on. Where it does fail, and it can, the recipe below swallows
# the status rather than the build stopping over a symlink.
#
# Hung off compilation and the help screen rather than off MAKECMDGOALS.
# Naming the goals would give every one of them a rule, including the
# misspelled ones: a typo that stops today with "No rule to make target" would
# instead find an empty rule, report nothing to be done, and exit 0. A build
# system that succeeds on "make check-fromat" is a worse trade than installing
# a symlink one command later.
#
# Every binary this tree builds reaches the two object rules below, host unit
# tests included, so one order-only prerequisite there covers every build
# entry point without listing any of them. help covers the case that builds
# nothing, which is what a bare make prints. clean, distclean and the two hook
# targets reach neither, so they skip this without being named.
HOOK_INSTALLER := scripts/install-git-hooks.sh
HOOK_STAMP := $(BUILD_DIR)/.hooks-installed

# The stamp records a run that reported success. An installer that could not
# reach the hooks directory returns non-zero and leaves no stamp, so the next
# make retries rather than remembering a failure as done; an unwritable build/
# fails the touch and is likewise retried. Neither can fail the build, which is
# what the trailing no-op is for: hooks are a convenience, and a checkout that
# cannot take them still has to compile.
$(HOOK_STAMP): | $(BUILD_DIR)
	@$(HOOK_INSTALLER) --quiet && touch $@ 2> /dev/null || :

# Build flavor guard.
#
# Objects compiled with -fsanitize=... cannot be linked into a binary built
# without it, and the failure surfaces as a wall of undefined
# ___asan_version_mismatch symbols that names neither cause nor cure. The
# sanitizer targets clean before they build, but nothing cleans after them, so
# the next ordinary "make elfuse" walks into it. Record the flavor and wipe the
# tree when it changes: the rebuild was unavoidable either way, since every
# object is instrumented differently, so this costs nothing beyond making the
# reason legible.
#
# Evaluated while the makefile is read rather than as a target, because the
# sanitizer lanes reach $(ELFUSE_BIN) through their own prerequisites and never
# run a phony guard hung off the elfuse target. Getting that wrong is worse than
# no guard: the stamp stays stale, the link succeeds, and an instrumented binary
# is handed back to a caller who asked for a plain one.
BUILD_FLAVOR := $(strip $(CFLAGS))
BUILD_FLAVOR_STAMP := $(BUILD_DIR)/.build-flavor

# Goals that build nothing, so nothing needs the tree in a known flavor. A
# goal-less invocation is one of them: .DEFAULT_GOAL is help, while
# MAKECMDGOALS stays empty, so filtering the skip list out of the goals and
# testing what remains covers both that and a mixed "make help elfuse".
#
# print-% is in the list because those goals only print variables, and because
# something other than a person invokes them: check-proof-targets.py shells out
# to "make print-verify-targets" and runs on every "make check". Without the
# skip, that sub-make evaluates the flavor guard with whatever CFLAGS its own
# environment produces, so running the scanner beside a sanitizer build wipes
# that build's objects from under it.
BUILD_FLAVOR_GOALS := $(filter-out clean distclean help print-%,$(MAKECMDGOALS))

ifneq ($(BUILD_FLAVOR_GOALS),)
BUILD_FLAVOR_PREV := $(shell cat $(BUILD_FLAVOR_STAMP) 2>/dev/null)

# What matters is whether objects exist that this build cannot use, so the two
# ways that happens are separated. A stamp that disagrees is one. No stamp at
# all beside objects is the other, since a tree written before this guard
# existed records nothing and its objects carry unknown flags. An empty tree
# with no stamp is neither, and treating it as a mismatch is what deleted
# scan-build's report directory on every fresh checkout.
BUILD_FLAVOR_OBJS := $(wildcard $(BUILD_DIR)/*.o $(BUILD_DIR)/*/*.o $(BUILD_DIR)/*/*/*.o)

ifneq ($(BUILD_FLAVOR_OBJS),)
ifeq ($(BUILD_FLAVOR_PREV),)
$(info   FLAVOR  build/ holds objects with no record of their CFLAGS, so they)
$(info           are being removed)
BUILD_FLAVOR_STALE := 1
else ifneq ($(BUILD_FLAVOR),$(BUILD_FLAVOR_PREV))
$(info   FLAVOR  build/ holds objects compiled with different CFLAGS, so they)
$(info           are being removed. Was: [$(BUILD_FLAVOR_PREV)])
$(info           Now: [$(BUILD_FLAVOR)])
BUILD_FLAVOR_STALE := 1
endif
endif

ifdef BUILD_FLAVOR_STALE
# Only the objects and their dependency files, not the directory. Other tools
# put their own output under build/ and are entitled to keep it: scan-build
# creates its report directory and then invokes make, so removing the tree here
# deletes the directory it is writing into and the analyzer dies on the next
# translation unit.
#
# What survived is the question, not how find reported it. Both of find's
# answers are to a different one: -delete descends into that same report
# directory, so an unreadable entry there exits non-zero with every removal
# having succeeded, and a removal that failed silently is invisible to stderr.
# Stopping is the point. Carrying on writes a stamp claiming a flavor the
# leftover objects do not have.
# Only the host objects and the dependency files that belong to them. A find
# over the whole tree also takes the .d files of the cross-compiled guest
# binaries, which are built with CROSS_TEST_CFLAGS and so have no flavor: the
# binary survives the wipe while the record of which headers it depends on does
# not, and editing tests/test-harness.h then stops rebuilding any of them. That
# was invisible while the sanitizer lanes still depended on "clean", which
# removed binary and .d together; dropping that prerequisite made the mismatch
# permanent, so the wipe's unit has to match the flavor's unit.
#
# A .d does not sit beside its object. DEPFLAGS above writes it flat under
# build/ with the path separators replaced by underscores, so the object
# build/syscall/casefold.o is described by build/syscall_casefold.d. Deriving
# the name by suffix substitution alone names a file that has never existed on
# this tree, which is a wipe that silently keeps every stale record it claims
# to remove.
BUILD_FLAVOR_DEPS := $(foreach o,$(BUILD_FLAVOR_OBJS),\
    $(BUILD_DIR)/$(subst /,_,$(patsubst $(BUILD_DIR)/%,%,$(basename $(o)))).d)
BUILD_FLAVOR_RM := $(shell rm -f $(BUILD_FLAVOR_OBJS) $(BUILD_FLAVOR_DEPS) \
    2>/dev/null; ls $(BUILD_FLAVOR_OBJS) $(BUILD_FLAVOR_DEPS) 2>/dev/null | head -3)
ifneq ($(BUILD_FLAVOR_RM),)
$(error FLAVOR: stale objects under $(BUILD_DIR) survived removal: $(BUILD_FLAVOR_RM))
endif
endif

$(shell mkdir -p $(BUILD_DIR) && printf '%s' '$(BUILD_FLAVOR)' > $(BUILD_FLAVOR_STAMP))
endif

# Pattern rules -- source to object.
# GENERATED_HEADERS are order-only prerequisites so clean builds have the
# build-generated includes available before compilation. .d files track the
# real header dependencies after the first compile. Generators whose output
# triggers a rebuild on input change (e.g., build/dispatch.h from
# src/syscall/dispatch.tbl) use explicit normal prerequisites where needed.

help: | $(HOOK_STAMP)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR) $(GENERATED_HEADERS) $(HOOK_STAMP)
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -I$(BUILD_DIR) -Isrc -c -o $@ $<

$(BUILD_DIR)/%.o: tests/%.c | $(BUILD_DIR) $(GENERATED_HEADERS) $(HOOK_STAMP)
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) $(DEPFLAGS) -I$(BUILD_DIR) -Isrc -c -o $@ $<

# Include generated dependency files (silently skip on first build)
-include $(wildcard $(BUILD_DIR)/*.d)

.PHONY: clean distclean

## Remove all build artifacts
clean:
	rm -rf $(BUILD_DIR)

## Remove build artifacts plus downloaded test fixtures (Alpine packages, kernel, initramfs, busybox)
distclean: clean
	rm -rf externals/test-fixtures
