#!/usr/bin/env bash

set -eu

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BUILD_CIRCUIT_V011="${BUILD_CIRCUIT_V011:-$HOME/src/circom-witnesscalc-build-circuit-v0.1.1/target/release/build-circuit}"
CIRCOM_CVM_DIR="$HOME/src/circom_cvm/target/release"
SNARKJS_DIR="$HOME/src/node_modules/.bin"

print_usage() {
    echo "Usage: $0 [-h]"
    echo
    echo "Run the full test pipeline:"
    echo "  1. cargo test with all feature flags"
    echo "  2. cargo clippy"
    echo "  3. test_circuits.sh (current build-circuit)"
    echo "  4. test_circuits.sh (build-circuit v0.1.1 with graph_v1 tag)"
    echo "  5. test_circuits_vm.sh"
    echo "  6. test_circuits_vm2.sh (only if circom supports --cvm)"
    echo
    echo "Environment variables:"
    echo "  BUILD_CIRCUIT_V011    Path to build-circuit v0.1.1 binary"
    echo "                        (default: ~/src/circom-witnesscalc-build-circuit-v0.1.1/target/release/build-circuit)"
    echo
    echo "Options:"
    echo "  -h    Print this usage and exit"
}

while getopts ":h" opt; do
    case $opt in
    h)
        print_usage
        exit 0
        ;;
    \?)
        echo "Error: Invalid option -$OPTARG" >&2
        exit 1
        ;;
    esac
done

# Add default paths to PATH if they exist
if [ -f "$CIRCOM_CVM_DIR/circom" ]; then
    export PATH="$CIRCOM_CVM_DIR:$PATH"
fi
if [ -d "$SNARKJS_DIR" ]; then
    export PATH="$SNARKJS_DIR:$PATH"
fi

# Check for required commands
if ! command -v circom &>/dev/null; then
    echo -e "${RED}Error: circom not found${NC}" >&2
    echo "Install circom or add it to PATH" >&2
    echo "For circom_cvm, build it at: $CIRCOM_CVM_DIR" >&2
    exit 1
fi

if ! command -v snarkjs &>/dev/null; then
    echo -e "${RED}Error: snarkjs not found${NC}" >&2
    echo "Install snarkjs or add it to PATH" >&2
    echo "Default location: $SNARKJS_DIR" >&2
    exit 1
fi

# Check if circom supports --cvm flag
circom_has_cvm=false
if circom --help 2>&1 | grep -q "\-\-cvm"; then
    circom_has_cvm=true
fi

step=0
total_steps=6

run_step() {
    step=$((step + 1))
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}[$step/$total_steps] $1${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

cd "$script_dir"

run_step "Running cargo test with all feature flags"
cargo test --release --workspace --all-features

run_step "Running cargo clippy"
cargo clippy --release --workspace --all-features -- -D warnings

run_step "Running test_circuits.sh (current build-circuit)"
./test_circuits.sh

run_step "Running test_circuits.sh (build-circuit v0.1.1 with graph_v1 tag)"
if [ ! -f "$BUILD_CIRCUIT_V011" ]; then
    echo -e "${YELLOW}Warning: build-circuit v0.1.1 not found at $BUILD_CIRCUIT_V011${NC}"
    echo -e "${YELLOW}Skipping graph_v1 compatibility tests${NC}"
    echo ""
    echo "To enable these tests, install build-circuit v0.1.1:"
    echo "  git clone --branch build-circuit/v0.1.1 https://github.com/iden3/circom-witnesscalc.git ~/src/circom-witnesscalc-build-circuit-v0.1.1"
    echo "  cd ~/src/circom-witnesscalc-build-circuit-v0.1.1"
    echo "  cargo build --release -p build-circuit"
else
    ./test_circuits.sh -b "$BUILD_CIRCUIT_V011" -t graph_v1
fi

run_step "Running test_circuits_vm.sh"
./test_circuits_vm.sh

run_step "Running test_circuits_vm2.sh"
if [ "$circom_has_cvm" = true ]; then
    ./test_circuits_vm2.sh
else
    echo -e "${YELLOW}Warning: circom does not support --cvm flag${NC}"
    echo -e "${YELLOW}Skipping test_circuits_vm2.sh (requires circom_cvm)${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All tests passed!${NC}"
echo -e "${GREEN}========================================${NC}"
