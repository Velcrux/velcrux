#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Velcrux Protocol Fuzzing Runner (Option AL / REQUIREMENTS.md §49, §50, §22)
#
# Runs in-process property fuzz suites and optional libFuzzer continuous runs.
# Enforces zero panics on malformed wire input bytes.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "======================================================================"
echo " Velcrux Protocol Fuzzing Suite & Parser Hardening Verification"
echo "======================================================================"

# 1. Run in-process deterministic property-based protocol fuzzing (100,000+ iterations)
echo ""
echo "[1/3] Running protocol decoder in-process fuzzing suite..."
cargo test --test protocol_fuzzing -- --nocapture

# 2. Run in-process live server stream fuzzing
echo ""
echo "[2/3] Running server stream adversarial fuzzing suite..."
cargo test --test server_fuzzing -- --nocapture

# 3. Run committed fuzz corpus regression test
echo ""
echo "[3/3] Running committed seed corpus boundary regression matrix..."
cargo test --test fuzz_corpus -- --nocapture

# 4. Optional libFuzzer execution if requested or available
if [[ "${1:-}" == "--libfuzzer" ]]; then
    if ! command -v cargo-fuzz &> /dev/null; then
        echo "Error: cargo-fuzz is not installed. Install via: cargo install cargo-fuzz"
        exit 1
    fi
    MAX_TIME="${2:-15}"
    echo ""
    echo "[libFuzzer] Running continuous coverage-guided fuzzing (${MAX_TIME}s per target)..."
    cd "${REPO_ROOT}/fuzz"
    TARGETS=("frame_decoder" "manifest_decoder" "path_validator" "config_parser" "cert_identity" "vbatch_decoder")
    for target in "${TARGETS[@]}"; do
        echo ">>> Fuzzing target: ${target} for ${MAX_TIME}s..."
        cargo fuzz run "${target}" -- -max_total_time="${MAX_TIME}" -workers=1
    done
    cd "${REPO_ROOT}"
fi

echo ""
echo "======================================================================"
echo " Fuzzing suite complete: ALL DECODERS PANIC-FREE (100% PASS)"
echo "======================================================================"
exit 0
