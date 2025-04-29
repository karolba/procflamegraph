BIN           ?= ../release-procflamegraph
VERBOSE       ?= 0
CXXFLAGS      ?= -std=gnu++23 -Wall -Wextra
TEST_BINARIES := $(patsubst %.cpp,artifacts/%,$(wildcard *.cpp))
TESTS         := $(patsubst %.expected-output,test/%,$(wildcard *.expected-output))

ifeq '$(VERBOSE)' '0'
  Q := @
else
  Q :=
endif

ifeq '$(VERBOSE)' '2'
  .SHELLFLAGS = -x -c
endif

.PHONY: all
all: $(TEST_BINARIES) $(TESTS)

procflamegraph: $(BIN)
	$(Q)ln -s $(BIN) procflamegraph

artifacts/%: %.cpp common.hpp Makefile
	$(Q)mkdir -p artifacts
	$(Q)$(CXX) $(CXXFLAGS) $(*F).cpp -o $@

artifacts/%.result: $(TEST_BINARIES) Makefile procflamegraph
	$(Q)mkdir -p artifacts
	$(Q)./$(*F).sh ./procflamegraph > $@

.PHONY: test/%
test/%: artifacts/%.result %.expected-output
	$(Q)diff -u $(*F).expected-output artifacts/$(*F).result && echo ok $(*F)

.PHONY: clean
clean:
	$(Q)rm -fv $(TEST_BINARIES) $(TESTS:test/%=artifacts/%.result)


