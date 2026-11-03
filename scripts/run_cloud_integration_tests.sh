#!/usr/bin/env bash
# ==============================================================================
# Velcrux Real Cloud Object Storage Integration Test Runner (ADR-064 / Option CV)
# ==============================================================================
# Executes live integration tests against containerized MinIO (S3),
# Azurite (Azure Blob), and Fake-GCS-Server (Google Cloud Storage) or
# falls back to the hermetic in-process TCP wire server.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKSPACE_ROOT}"

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}==============================================================================${NC}"
echo -e "${BOLD}${BLUE}   Velcrux Real Cloud Storage Containerized Integration Test Matrix          ${NC}"
echo -e "${BOLD}${BLUE}           (MinIO S3 / Azurite / Fake-GCS / FastCDC Deduplication)           ${NC}"
echo -e "${BOLD}${BLUE}==============================================================================${NC}\n"

DOCKER_STARTED=false

cleanup() {
    if [ "$DOCKER_STARTED" = true ]; then
        echo -e "\n${YELLOW}--> Stopping cloud test containers...${NC}"
        docker compose stop minio azurite fake-gcs-server 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Check if Docker is available and if MinIO is running
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        echo -e "${YELLOW}--> Docker daemon detected. Checking container status...${NC}"
        if ! curl -s -f "http://127.0.0.1:9000/minio/health/live" >/dev/null 2>&1; then
            echo -e "${YELLOW}--> Starting MinIO, Azurite, and Fake-GCS containers...${NC}"
            docker compose up -d minio azurite fake-gcs-server
            DOCKER_STARTED=true
            echo -e "${YELLOW}--> Waiting for MinIO readiness...${NC}"
            for i in {1..30}; do
                if curl -s -f "http://127.0.0.1:9000/minio/health/live" >/dev/null 2>&1; then
                    echo -e "${GREEN}--> MinIO is healthy and ready!${NC}"
                    export VELCRUX_S3_TEST_ENDPOINT="http://127.0.0.1:9000"
                    break
                fi
                sleep 1
            done
        else
            echo -e "${GREEN}--> Existing MinIO endpoint detected at http://127.0.0.1:9000${NC}"
            export VELCRUX_S3_TEST_ENDPOINT="http://127.0.0.1:9000"
        fi
    fi
fi

if [ -z "${VELCRUX_S3_TEST_ENDPOINT:-}" ]; then
    echo -e "${YELLOW}--> External MinIO not running; using hermetic in-process TCP wire server (127.0.0.1:0).${NC}"
fi

echo -e "\n${YELLOW}--> Running Storage Cloud Harness Test Suite...${NC}"
cargo test -p velcrux-core --test storage_cloud_harness -- --nocapture

echo -e "\n${GREEN}${BOLD}✓ All Cloud Storage Containerized Integration Tests Passed Successfully!${NC}\n"
