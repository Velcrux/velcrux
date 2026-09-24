#!/usr/bin/env bash
set -euo pipefail

# Velcrux Docker Entrypoint (docs/OPERATIONS.md §9)

CONFIG_FILE="${1:-/etc/velcrux/server.toml}"

# Ensure directories exist
mkdir -p /data/velcrux/files/.velcrux-staging /data/velcrux/chunks /var/lib/velcrux /etc/velcrux

# If TLS certificates are missing, generate dev certificates on the fly
if [[ ! -f /etc/velcrux/server.crt || ! -f /etc/velcrux/server.key ]]; then
    echo "Notice: Certificates missing in /etc/velcrux, generating dev PKI..."
    TMP_PKI="/tmp/velcrux-pki"
    mkdir -p "$TMP_PKI"
    /usr/local/bin/velcruxd gen-dev-ca --out "$TMP_PKI" --days 365
    /usr/local/bin/velcruxd gen-dev-cert --ca "$TMP_PKI" --out "$TMP_PKI" --host localhost,127.0.0.1 --hours 8760
    
    cp "$TMP_PKI/ca.crt" /etc/velcrux/clients-ca.crt
    cp "$TMP_PKI/server.crt" /etc/velcrux/server.crt
    cp "$TMP_PKI/server.key" /etc/velcrux/server.key
    chmod 0600 /etc/velcrux/server.key
    echo "Dev PKI generated at /etc/velcrux."
fi

echo "Starting velcruxd with config: ${CONFIG_FILE}"
exec /usr/local/bin/velcruxd run --config "${CONFIG_FILE}"
