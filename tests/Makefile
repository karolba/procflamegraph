BIN             ?= ../release-procflamegraph
VERBOSE         ?= 0
CXXFLAGS        ?= -std=gnu++23 -Wall -Wextra
HELPER_BINARIES := $(patsubst helpers/%.cpp,artifacts/%,$(wildcard helpers/*.cpp))
TESTS           := $(patsubst %.expected-output,test/%,$(wildcard *.expected-output))

ifeq '$(VERBOSE)' '0'
  Q := @
else
  Q :=
endif

ifeq '$(VERBOSE)' '2'
  .SHELLFLAGS = -x -c
endif

.PHONY: all
all: $(HELPER_BINARIES) $(TESTS)

procflamegraph: $(BIN)
	$(Q)ln -fs $(BIN) procflamegraph

artifacts/%: helpers/%.cpp helpers/common.hpp Makefile
	$(Q)mkdir -p artifacts
	$(CXX) $(CXXFLAGS) helpers/$(*F).cpp -o $@

# Extra flags
artifacts/no-main: CXXFLAGS += -nostdlib -static

artifacts/%.result: $(HELPER_BINARIES) Makefile procflamegraph
	$(Q)mkdir -p artifacts
	$(Q)./$(*F).sh ./procflamegraph > $@

.PHONY: test/%
test/%: artifacts/%.result %.expected-output
	$(Q)diff -u $(*F).expected-output artifacts/$(*F).result && echo ok $(*F)

.PHONY: clean
clean:
	$(Q)rm -fv $(HELPER_BINARIES) $(TESTS:test/%=artifacts/%.result)


