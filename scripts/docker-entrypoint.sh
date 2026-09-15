#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/velcrux/server.toml}"

# Ensure directories exist
mkdir -p /var/lib/velcrux /data/velcrux/files /data/velcrux/files/.velcrux-staging /etc/velcrux

# Auto-provision ephemeral dev certificates if missing
if [[ ! -f /etc/velcrux/server.crt ]]; then
    echo "==> No server certificate found at /etc/velcrux/server.crt. Provisioning development PKI..."
    DEV_PKI="/tmp/dev_pki"
    mkdir -p "${DEV_PKI}/ca" "${DEV_PKI}/server" "${DEV_PKI}/client"
    
    velcruxd gen-dev-ca --out "${DEV_PKI}/ca" --days 30
    velcruxd gen-dev-cert --out "${DEV_PKI}/server" --ca "${DEV_PKI}/ca" --host "localhost,127.0.0.1" --hours 24
    velcruxd gen-dev-cert --out "${DEV_PKI}/client" --ca "${DEV_PKI}/ca" --client "admin" --hours 24

    cp "${DEV_PKI}/server/localhost.crt" /etc/velcrux/server.crt
    cp "${DEV_PKI}/server/localhost.key" /etc/velcrux/server.key
    cp "${DEV_PKI}/ca/ca.crt" /etc/velcrux/clients-ca.crt
    
    # Also save client certs for easy testing inside container
    mkdir -p /etc/velcrux/client
    cp "${DEV_PKI}/client/admin.crt" /etc/velcrux/client/client.crt
    cp "${DEV_PKI}/client/admin.key" /etc/velcrux/client/client.key
    cp "${DEV_PKI}/ca/ca.crt" /etc/velcrux/client/ca.crt
    chmod 0600 /etc/velcrux/client/client.key

    rm -rf "${DEV_PKI}"
    echo "==> Development certificates provisioned."
fi

# Ensure private key is strictly readable by owner only (0600) per SECURITY.md §7
if [[ -f /etc/velcrux/server.key ]]; then
    chmod 0600 /etc/velcrux/server.key
fi

# Provide fallback grants file if missing
if [[ ! -f /etc/velcrux/grants.toml ]]; then
    cat <<EOF > /etc/velcrux/grants.toml
[[grant]]
identity = "admin"
path = "/"
permissions = ["upload", "download", "list", "delete", "sync", "resume", "admin"]
EOF
fi

echo "==> Starting velcruxd with config: ${CONFIG_FILE}"
exec velcruxd run --config "${CONFIG_FILE}"
