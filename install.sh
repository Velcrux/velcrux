#!/usr/bin/env bash
# ==============================================================================
# Velcrux Installer for Linux & macOS
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Velcrux/velcrux/main/install.sh | bash
# Or with options:
#   INSTALL_DIR=~/.local/bin bash install.sh
#   VERSION=v0.1.0 bash install.sh
# ==============================================================================

set -euo pipefail

REPO="Velcrux/velcrux"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REQUESTED_VERSION="${VERSION:-latest}"

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"; }
log_success() { echo -e "${GREEN}==>${NC} ${BOLD}$1${NC}"; }
log_warn() { echo -e "${YELLOW}WARNING:${NC} $1"; }
log_error() { echo -e "${RED}ERROR:${NC} $1" >&2; }

# 1. Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  PLATFORM="linux" ;;
    darwin) PLATFORM="darwin" ;;
    *)
        log_error "Unsupported operating system: $OS. Please install from source or use Windows PowerShell install.ps1."
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH_NAME="amd64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *)
        log_error "Unsupported CPU architecture: $ARCH"
        exit 1
        ;;
esac

TARGET="${PLATFORM}-${ARCH_NAME}"
log_info "Detected system: ${PLATFORM} (${ARCH_NAME})"

# 3. Resolve Release Version
if [ "$REQUESTED_VERSION" = "latest" ]; then
    log_info "Resolving latest release tag from GitHub..."
    RESOLVED_TAG="$(curl -sIL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" | sed 's#.*/tag/##')"
    if [ -z "$RESOLVED_TAG" ] || [ "$RESOLVED_TAG" = "releases" ]; then
        RESOLVED_TAG="v0.1.0"
        log_warn "Could not resolve latest tag from GitHub (no releases yet). Defaulting to ${RESOLVED_TAG}."
    fi
    VERSION="$RESOLVED_TAG"
else
    VERSION="$REQUESTED_VERSION"
fi

log_info "Installing Velcrux version: ${VERSION}"

# 4. Prepare Download
TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ARCHIVE_NAME="velcrux-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS.txt"

log_info "Downloading ${ARCHIVE_NAME}..."
if ! curl -fSL --progress-bar "$DOWNLOAD_URL" -o "${TMP_DIR}/${ARCHIVE_NAME}"; then
    log_error "Failed to download ${DOWNLOAD_URL}."
    log_error "Please check if release ${VERSION} exists at https://github.com/${REPO}/releases"
    exit 1
fi

# 5. Checksum Verification
log_info "Verifying SHA256 checksum..."
if curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/SHA256SUMS.txt" 2>/dev/null; then
    EXPECTED_HASH="$(grep "${ARCHIVE_NAME}" "${TMP_DIR}/SHA256SUMS.txt" | awk '{print $1}' || true)"
    if [ -n "$EXPECTED_HASH" ]; then
        if command -v sha256sum &>/dev/null; then
            ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${ARCHIVE_NAME}" | awk '{print $1}')"
        elif command -v shasum &>/dev/null; then
            ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${ARCHIVE_NAME}" | awk '{print $1}')"
        else
            ACTUAL_HASH=""
        fi

        if [ -n "$ACTUAL_HASH" ]; then
            if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
                log_error "Checksum verification failed!"
                log_error "Expected: ${EXPECTED_HASH}"
                log_error "Actual:   ${ACTUAL_HASH}"
                exit 1
            fi
            log_success "Checksum verified: ${ACTUAL_HASH:0:16}..."
        fi
    fi
else
    log_warn "SHA256SUMS.txt not found on release; skipping checksum verification."
fi

# 6. Extract Archive
log_info "Extracting binaries..."
tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "$TMP_DIR"
STAGE_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name "velcrux-*" | head -n 1)"

if [ -z "$STAGE_DIR" ] || [ ! -f "${STAGE_DIR}/velcrux" ]; then
    log_error "Extracted archive does not contain expected binaries."
    exit 1
fi

# 7. Install to target directory
# If /usr/local/bin requires root and user isn't root, fallback to ~/.local/bin or request sudo
SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
    if [ "$INSTALL_DIR" = "/usr/local/bin" ]; then
        if command -v sudo &>/dev/null && [ -t 0 ]; then
            SUDO="sudo"
        else
            log_warn "$INSTALL_DIR is not writable without root. Falling back to ~/.local/bin"
            INSTALL_DIR="$HOME/.local/bin"
        fi
    else
        if command -v sudo &>/dev/null; then
            SUDO="sudo"
        fi
    fi
fi

$SUDO mkdir -p "$INSTALL_DIR"
log_info "Installing binaries to ${INSTALL_DIR}..."
$SUDO cp "${STAGE_DIR}/velcrux" "${STAGE_DIR}/velcruxd" "$INSTALL_DIR/"
$SUDO chmod +x "${INSTALL_DIR}/velcrux" "${INSTALL_DIR}/velcruxd"

log_success "Velcrux installed successfully to ${INSTALL_DIR}!"
echo ""
echo -e "  ${BOLD}velcrux${NC}   : Client CLI (${INSTALL_DIR}/velcrux)"
echo -e "  ${BOLD}velcruxd${NC}  : Server Daemon (${INSTALL_DIR}/velcruxd)"
echo ""

# Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    log_warn "${INSTALL_DIR} is not currently in your PATH."
    echo "  Add it by running:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
fi

echo "To verify the installation, run:"
echo "  velcrux --help"
echo "  velcruxd --help"
