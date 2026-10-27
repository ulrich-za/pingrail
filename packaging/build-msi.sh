#!/usr/bin/env bash
# Build the Windows installer, dist/pingrail-<version>-x64.msi.
#
# On Windows, use MSYS2 (or run packaging\windows\build-msi.ps1, which does
# all of this for you). Install MSYS2 (winget install --id MSYS2.MSYS2), open
# "MSYS2 UCRT64" and run once:
#   pacman -Syu        (repeat if it asks you to restart the terminal)
#   pacman -S --needed mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-msitools perl make
#
# On Linux or WSL (Ubuntu/Debian), run once:
#   sudo apt install -y build-essential perl gcc-mingw-w64-x86-64 wixl
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#   source "$HOME/.cargo/env"
#   rustup target add x86_64-pc-windows-gnu
#
# Then, from the unpacked source folder:
#   packaging/build-msi.sh
#
# Options:
#   --exe FILE   package an already-built pingrail.exe instead of compiling
set -euo pipefail
cd "$(dirname "$0")/.."

EXE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --exe) EXE="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST=dist
MSI="$DIST/pingrail-$VERSION-x64.msi"
case "$(uname -s)" in
    MINGW*|MSYS*|UCRT*|CLANG*) ON_WINDOWS=1 ;;
    *) ON_WINDOWS=0 ;;
esac
if [ "$ON_WINDOWS" = 1 ]; then
    # MSYS2 builds natively with its own gcc (the repo's linker setting is
    # for cross-compiling from Linux).
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=gcc
fi

missing() { echo "error: $1 isn't installed. See the setup steps at the top of $0." >&2; exit 1; }
command -v wixl >/dev/null || missing "wixl (msitools)"
command -v cargo >/dev/null || missing "Rust (cargo)"
# OpenSSL (for passkeys) is compiled into pingrail.exe; its build needs these.
command -v perl >/dev/null || missing "perl"
command -v make >/dev/null || missing "make"

if [ -z "$EXE" ]; then
    if [ "$ON_WINDOWS" = 1 ]; then
        command -v gcc >/dev/null || missing "gcc"
        echo "==> Compiling pingrail $VERSION (Windows, x86-64)"
        cargo build --release --locked
        EXE="${CARGO_TARGET_DIR:-target}/release/pingrail.exe"
    else
        command -v x86_64-w64-mingw32-gcc >/dev/null || missing "gcc-mingw-w64-x86-64"
        if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx x86_64-pc-windows-gnu; then
            echo "error: run 'rustup target add x86_64-pc-windows-gnu' first." >&2
            exit 1
        fi
        echo "==> Compiling pingrail $VERSION for Windows (x86-64)"
        cargo build --release --locked --target x86_64-pc-windows-gnu
        EXE="${CARGO_TARGET_DIR:-target}/x86_64-pc-windows-gnu/release/pingrail.exe"
    fi
fi
[ -f "$EXE" ] || { echo "error: $EXE not found" >&2; exit 1; }

echo "==> Building the table checker"
# Runs on the build machine (no cross-compiling), into its own folder.
cargo build --release --locked --quiet \
    --manifest-path packaging/tools/msisort/Cargo.toml --target-dir target/msisort
MSISORT=target/msisort/release/msisort
[ -x "$MSISORT" ] || MSISORT="$MSISORT.exe"

echo "==> Staging files"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "$EXE" "$STAGE/pingrail.exe"
cp packaging/windows/pingrail.ico README.md LICENSE NOTICE THIRD-PARTY-NOTICES.txt "$STAGE/"
cp packaging/linux/pingrail.toml "$STAGE/pingrail.toml.example"
mkdir -p "$STAGE/fonts"
cp assets/fonts/*.ttf assets/fonts/LICENSE-DejaVu.txt "$STAGE/fonts/"

echo "==> Building $MSI"
mkdir -p "$DIST"
SOURCE_DIR="$STAGE"
if [ "$ON_WINDOWS" = 1 ]; then
    SOURCE_DIR=$(cygpath -m "$STAGE")
fi
wixl -a x64 -D Version="$VERSION" -D SourceDir="$SOURCE_DIR" -o "$MSI" packaging/windows/pingrail.wxs
# wixl can store a table's rows out of primary-key order, which Windows
# Installer rejects with error 2229. Sort them, then check every table.
"$MSISORT" --fix "$MSI" >/dev/null || { echo "error: $MSI still has unsorted tables" >&2; exit 1; }
"$MSISORT" "$MSI" >/dev/null
# Without pingrail.exe's version in the File table, upgrades fail with error
# 2753 (Windows Installer won't replace the installed, versioned exe).
if command -v msiinfo >/dev/null; then
    msiinfo export "$MSI" File | tr -d '\r' \
        | awk -F'\t' -v v="$VERSION.0" '$1 == "pingrailExe" { found = ($5 == v) } END { exit !found }' \
        || { echo "error: $MSI doesn't record pingrail.exe's version ($VERSION.0)" >&2; exit 1; }
fi

echo "==> Done"
ls -l "$MSI"
sha256sum "$MSI"
