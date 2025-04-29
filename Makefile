TARGET_arm64   = aarch64-unknown-linux-musl
TARGET_aarch64 = aarch64-unknown-linux-musl
TARGET_x86_64  = x86_64-unknown-linux-musl
TARGET         = $(TARGET_$(shell uname -m))
.SHELLFLAGS    = -x -c

ifeq '$(shell uname)' 'Darwin'
  ORB := orb
else
  ORB :=
endif

.PHONY: all
all:
	@make build
	@make cargo-tests
	@make integration-tests

.PHONY: build
build:
	@$(ORB) cargo build --target $(TARGET)

.PHONY: cargo-tests
cargo-tests:
	@$(ORB) cargo test --target $(TARGET)

.PHONY: integration-tests
integration-tests:
	@$(ORB) make -k -j $$(nproc) -C tests BIN=../target/$(TARGET)/debug/procflamegraph

.PHONY: release
release:
	env RUSTFLAGS="-Ctarget-feature=+crt-static -Clink-self-contained=yes --remap-path-prefix=$$HOME=~" \
		uv run \
		--isolated \
		--with cargo-zigbuild==0.20.0 \
		cargo-zigbuild \
		zigbuild \
		--release \
		--target aarch64-unknown-linux-musl \
		--target x86_64-unknown-linux-musl

