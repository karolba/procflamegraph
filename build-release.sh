#!/bin/bash

export RUSTFLAGS="--remap-path-prefix=$HOME=~"
uvx cargo-zigbuild zigbuild \
    --release \
    --target aarch64-unknown-linux-musl \
    #--target riscv64gc-unknown-linux-musl \
    #--target arm-unknown-linux-musleabi \
    #--target arm-unknown-linux-musleabihf \
    #--target i686-unknown-linux-musl \
    #--target powerpc64le-unknown-linux-musl \
    #--target x86_64-unknown-linux-musl


# todo add more targets
# broken: --target loongarch64-unknown-linux-musl \
