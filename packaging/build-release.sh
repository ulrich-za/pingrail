#!/usr/bin/env bash
# Build release artifacts into dist/:
#   pingrail_<ver>-1_amd64.deb   Debian/Ubuntu x86-64
#   pingrail_<ver>-1_arm64.deb   Raspberry Pi OS / Ubuntu arm64
#   pingrail-<ver>-x64.msi       Windows installer
#   pingrail-<ver>-windows-x64.exe  portable Windows binary
#
# Linux binaries are linked against glibc 2.28 with cargo-zigbuild, so the
# packages run on Debian 10+, Ubuntu 20.04+ and Raspberry Pi OS Buster or later
# regardless of how new the build host is.
#
# Prerequisites (Debian/Ubuntu build host):
#   sudo apt install gcc-mingw-w64-x86-64 wixl
#   rustup target add x86_64-unknown-linux-gnu x86_64-pc-windows-gnu aarch64-unknown-linux-gnu
#   pip install ziglang          # or install Zig 0.13+ another way
#   cargo install cargo-deb cargo-zigbuild
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Third-party notices"
python3 packaging/tools/third_party.py > THIRD-PARTY-NOTICES.txt

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST=dist
mkdir -p "$DIST"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}
GLIBC=${GLIBC:-2.28}
export CC_x86_64_pc_windows_gnu=${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}

for TRIPLE in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
    echo "==> Linux $TRIPLE (glibc $GLIBC)"
    cargo zigbuild --release --target "$TRIPLE.$GLIBC"
    cargo deb --no-build --target "$TRIPLE" --output "$DIST/"
done

echo "==> Windows x64"
cargo build --release --target x86_64-pc-windows-gnu
WINEXE=target/x86_64-pc-windows-gnu/release/pingrail.exe
cp "$WINEXE" "$DIST/pingrail-$VERSION-windows-x64.exe"

packaging/build-msi.sh --exe "$WINEXE"

echo "==> Source"
git archive --format=zip --prefix="pingrail-$VERSION/" -o "$DIST/pingrail-$VERSION-src.zip" HEAD 2>/dev/null \
    || echo "   (not a git checkout: skipped the source zip)"

echo "==> Done"
ls -l "$DIST"
