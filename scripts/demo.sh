#!/usr/bin/env bash
# ==============================================================================
# Velcrux Interactive Showcase & Quickstart Demo
# Demonstrates QUIC sync, FastCDC delta transfer, dedup, and Prometheus metrics
# ==============================================================================

set -euo pipefail

# Ensure macOS CommandLineTools toolchain if on Darwin
if [[ "$(uname)" == "Darwin" && -z "${DEVELOPER_DIR:-}" ]]; then
    export DEVELOPER_DIR="/Library/Developer/CommandLineTools"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}==============================================================================${NC}"
echo -e "${BOLD}${BLUE}                   Velcrux Bulk Transfer Demonstration                       ${NC}"
echo -e "${BOLD}${BLUE}       (QUIC | FastCDC Delta Sync | Chunk-Store Dedup | Metrics)             ${NC}"
echo -e "${BOLD}${BLUE}==============================================================================${NC}\n"

TMP_DIR="$(mktemp -d /tmp/velcrux_demo_XXXXXX)"
cleanup() {
    echo -e "\n${YELLOW}--> Shutting down ephemeral services and cleaning up...${NC}"
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
    echo -e "${GREEN}Cleanup complete.${NC}"
}
trap cleanup EXIT

# 1. Build Binaries
echo -e "${CYAN}[Step 1/6]${NC} Building project binaries..."
cargo build -q -p velcrux-server -p velcrux-client
VELCRUXD="${WORKSPACE_ROOT}/target/debug/velcruxd"
VELCRUX="${WORKSPACE_ROOT}/target/debug/velcrux"

# 2. Provision Ephemeral PKI and Server
echo -e "\n${CYAN}[Step 2/6]${NC} Provisioning development mTLS PKI and launching velcruxd..."
PKI_DIR="${TMP_DIR}/pki"
STORAGE_DIR="${TMP_DIR}/storage"
STAGING_DIR="${TMP_DIR}/staging"
STATE_DB="${TMP_DIR}/state.db"
CHUNK_STORE="${TMP_DIR}/chunks"
mkdir -p "${PKI_DIR}" "${STORAGE_DIR}" "${STAGING_DIR}" "${CHUNK_STORE}"

"${VELCRUXD}" gen-dev-ca --out "${PKI_DIR}/ca" --days 30 >/dev/null
"${VELCRUXD}" gen-dev-cert --out "${PKI_DIR}/server" --ca "${PKI_DIR}/ca" --host "localhost" --hours 24 >/dev/null
"${VELCRUXD}" gen-dev-cert --out "${PKI_DIR}/client" --ca "${PKI_DIR}/ca" --client "demo-user" --hours 24 >/dev/null

chmod 0600 "${PKI_DIR}/server/localhost.key" "${PKI_DIR}/client/demo-user.key" "${PKI_DIR}/ca/ca.key"

GRANTS_FILE="${TMP_DIR}/grants.toml"
cat <<EOF > "${GRANTS_FILE}"
[[grant]]
identity = "demo-user"
path = "/"
permissions = ["upload", "download", "list", "sync", "resume", "admin"]
EOF

SERVER_CONF="${TMP_DIR}/server.toml"
cat <<EOF > "${SERVER_CONF}"
[network]
listen = "127.0.0.1:17443"
idle_timeout = "60s"
keepalive = "15s"

[security]
certificate = "${PKI_DIR}/server/localhost.crt"
private_key = "${PKI_DIR}/server/localhost.key"
client_ca = "${PKI_DIR}/ca/ca.crt"
grants = "${GRANTS_FILE}"

[storage]
root = "${STORAGE_DIR}"
staging = "${STAGING_DIR}"
state_db = "${STATE_DB}"

[telemetry]
metrics_listen = "127.0.0.1:19443"
EOF

"${VELCRUXD}" run --config "${SERVER_CONF}" > "${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 1.2

# Verify server mTLS connection
PONG="$("${VELCRUX}" --ca "${PKI_DIR}/ca/ca.crt" \
             --cert "${PKI_DIR}/client/demo-user.crt" \
             --key "${PKI_DIR}/client/demo-user.key" \
             --sni localhost \
             ping "velcrux://127.0.0.1:17443")"
echo -e "Server response: ${GREEN}${PONG}${NC}"

# 3. Create Sample Dataset
echo -e "\n${CYAN}[Step 3/6]${NC} Generating sample dataset..."
SRC_DIR="${TMP_DIR}/source_dataset"
DST_DIR="${TMP_DIR}/destination_dataset"
mkdir -p "${SRC_DIR}" "${DST_DIR}"

echo "Velcrux bulk transfer protocol document" > "${SRC_DIR}/README.txt"
# Create a 4 MiB synthetic binary asset
python3 -c "import os; open('${SRC_DIR}/asset_data.bin', 'wb').write(os.urandom(4 * 1024 * 1024))"
echo '{"status": "initialized", "version": 1}' > "${SRC_DIR}/metadata.json"

# Place an extraneous orphan file in destination
echo "Old extraneous file" > "${DST_DIR}/orphan.txt"

# 4. Dry-Run Demonstration
echo -e "\n${CYAN}[Step 4/6]${NC} Running directory sync preview with ${BOLD}--dry-run${NC}..."
"${VELCRUX}" sync "${SRC_DIR}" "${DST_DIR}" --dry-run

# 5. Initial Full Synchronization with FastCDC and Deduplication
echo -e "\n${CYAN}[Step 5/6]${NC} Executing initial sync with FastCDC and chunk-store deduplication..."
"${VELCRUX}" sync "${SRC_DIR}" "${DST_DIR}" --cdc --dedup --chunk-store "${CHUNK_STORE}"

# Verify destination received all files
if [[ -f "${DST_DIR}/asset_data.bin" ]] && [[ -f "${DST_DIR}/README.txt" ]]; then
    echo -e "${GREEN}Initial synchronization successful! All files staged and committed.${NC}"
fi

# 6. Modify File in the Middle & Re-sync (Demonstrating FastCDC Delta Savings)
echo -e "\n${CYAN}[Step 6/6]${NC} Modifying a 64 KiB block in the middle of asset_data.bin and re-syncing..."
# Overwrite 64 KiB at offset 1 MiB
python3 -c "with open('${SRC_DIR}/asset_data.bin', 'r+b') as f: f.seek(1024 * 1024); f.write(b'MODIFIED_PAYLOAD_FOR_DEMO' * 2500)"
echo "New changelog entry" > "${SRC_DIR}/changelog.txt"

echo -e "Re-syncing with ${BOLD}--cdc --delete-after${NC}..."
"${VELCRUX}" sync "${SRC_DIR}" "${DST_DIR}" --cdc --delete-after --dedup --chunk-store "${CHUNK_STORE}"

if [[ ! -f "${DST_DIR}/orphan.txt" ]] && [[ -f "${DST_DIR}/changelog.txt" ]]; then
    echo -e "${GREEN}Delta synchronization completed! Orphan deleted safely, changes merged with content reuse.${NC}"
fi

# Live Prometheus Metrics
echo -e "\n${BOLD}${BLUE}==============================================================================${NC}"
echo -e "${BOLD}${BLUE}                   Live Prometheus Metrics (Scraped from /metrics)           ${NC}"
echo -e "${BOLD}${BLUE}==============================================================================${NC}"
curl -s http://127.0.0.1:19443/metrics | grep -v '^#' | grep -v '^$'

echo -e "\n${BOLD}${GREEN}==============================================================================${NC}"
echo -e "${BOLD}${GREEN}                     Demo Completed Successfully!                            ${NC}"
echo -e "${BOLD}${GREEN}==============================================================================${NC}\n"
