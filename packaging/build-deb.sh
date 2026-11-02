#!/usr/bin/env bash
# ==============================================================================
# Velcrux Debian/Ubuntu Package Builder
# Usage: ./packaging/build-deb.sh <target-arch: amd64|arm64> <version> [bin-dir] [output-dir]
# ==============================================================================

set -euo pipefail

ARCH="${1:-amd64}"
VERSION="${2:-0.1.0}"
BIN_DIR="${3:-target/release}"
OUTPUT_DIR="${4:-dist}"

PACKAGE_NAME="velcrux_${VERSION}_${ARCH}"
ROOT_DIR="target/debian/${PACKAGE_NAME}"

echo "Building Debian package: ${PACKAGE_NAME}.deb..."

rm -rf "$ROOT_DIR"
mkdir -p "$ROOT_DIR/DEBIAN"
mkdir -p "$ROOT_DIR/usr/local/bin"
mkdir -p "$ROOT_DIR/etc/velcrux"
mkdir -p "$ROOT_DIR/lib/systemd/system"
mkdir -p "$ROOT_DIR/usr/share/bash-completion/completions"
mkdir -p "$ROOT_DIR/usr/share/zsh/vendor-completions"
mkdir -p "$ROOT_DIR/usr/share/fish/vendor_completions.d"
mkdir -p "$ROOT_DIR/usr/share/doc/velcrux"

# 1. Copy binaries
cp "${BIN_DIR}/velcrux" "$ROOT_DIR/usr/local/bin/velcrux"
cp "${BIN_DIR}/velcruxd" "$ROOT_DIR/usr/local/bin/velcruxd"
chmod 755 "$ROOT_DIR/usr/local/bin/velcrux" "$ROOT_DIR/usr/local/bin/velcruxd"

# 2. Control files
cat packaging/debian/control | sed "s/^Architecture: .*/Architecture: ${ARCH}/" | sed "s/^Version: .*/Version: ${VERSION}/" > "$ROOT_DIR/DEBIAN/control"
cp packaging/debian/postinst "$ROOT_DIR/DEBIAN/postinst"
cp packaging/debian/prerm "$ROOT_DIR/DEBIAN/prerm"
chmod 755 "$ROOT_DIR/DEBIAN/postinst" "$ROOT_DIR/DEBIAN/prerm"

# 3. Systemd units & configs
cp packaging/systemd/velcruxd.service "$ROOT_DIR/lib/systemd/system/velcruxd.service"
cp packaging/systemd/velcrux.service "$ROOT_DIR/lib/systemd/system/velcrux.service"
cp packaging/etc/velcrux/server.toml "$ROOT_DIR/etc/velcrux/server.toml.example"
cp packaging/etc/velcrux/grants.toml "$ROOT_DIR/etc/velcrux/grants.toml.example"
cp README.md LICENSE-APACHE LICENSE-MIT "$ROOT_DIR/usr/share/doc/velcrux/" 2>/dev/null || true

# 4. Generate completions if binaries are executable on host
if "$ROOT_DIR/usr/local/bin/velcrux" --version >/dev/null 2>&1; then
    "$ROOT_DIR/usr/local/bin/velcrux" completions bash > "$ROOT_DIR/usr/share/bash-completion/completions/velcrux" 2>/dev/null || true
    "$ROOT_DIR/usr/local/bin/velcrux" completions zsh > "$ROOT_DIR/usr/share/zsh/vendor-completions/_velcrux" 2>/dev/null || true
    "$ROOT_DIR/usr/local/bin/velcrux" completions fish > "$ROOT_DIR/usr/share/fish/vendor_completions.d/velcrux.fish" 2>/dev/null || true
fi

# 5. Build .deb package
mkdir -p "$OUTPUT_DIR"
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "$ROOT_DIR" "${OUTPUT_DIR}/${PACKAGE_NAME}.deb"
    echo "Successfully generated: ${OUTPUT_DIR}/${PACKAGE_NAME}.deb"
else
    echo "dpkg-deb not found; packaged directory staging preserved at: ${ROOT_DIR}"
fi

