#!/usr/bin/env bash

set -eux

required_commands=(circom snarkjs cargo node cmp)

RED='\033[0;31m'
NC='\033[0m' # No Color

for cmd in "${required_commands[@]}"; do
	if ! command -v "$cmd" &> /dev/null; then
		echo -e "${RED}\`$cmd\` command could not be found${NC}"
		exit 1
	fi
done

if ! circom --help | grep -q "\-\-cvm"; then
  echo -e "${RED}found circom version does not support --cvm flag.${NC}"
  exit 1
fi

workdir="$(pwd)/test_working_dir_vm2"

if [ ! -d "$workdir" ]; then
	echo "Creating working directory $workdir"
	mkdir "$workdir"
fi

print_usage() {
    echo "Usage: $0 [-h] [-l <inlcude_path>] [file1 ...]"
    echo
    echo "Options:"
    echo "  -l <include_path>      Path to include directory. Can be specified multiple times"
    echo "  -h                     Print this usage and exit"
    echo
    echo "Positional Arguments:"
    echo "  file1       Circom circuit file. May be multiple. If none provided, all circuits in test_circuits/ directory processed."
    echo
    echo "Examples:"
    echo "  $0 test_circuits/circuit1.circom"
}

declare -a library_paths

while getopts ":p:l:h" opt; do
  case $opt in
    h)
        print_usage
        exit 0
        ;;
    l)
        library_paths+=("$OPTARG")
        ;;
    :)
        echo "Error: -$OPTARG requires a value" >&2;
        exit 1
        ;;
    \?)
        echo "Error: Invalid option -$OPTARG" >&2;
        exit 1
        ;;
  esac
done

# Shift past the named options to access positional arguments
shift $((OPTIND - 1))

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "script dir ${script_dir}"

if [ ${#library_paths} -eq 0 ]; then
    library_paths+=("${script_dir}/test_deps/circomlib/circuits")
fi

declare -a include_args

for arg in "${library_paths[@]}"; do
    if [ ! -d "$arg" ]; then
      echo -e "${RED}include path not found at $arg${NC}"
      exit 1
    fi
    include_args+=("-l" "$arg")
done

pushd "${script_dir}" > /dev/null
# to build with debug vm2 execution, run:
cargo build --release --features "debug_vm2"
# cargo build --release
popd > /dev/null

function test_circuit() {
  local circuit_path=$1
  echo "Running $circuit_path"
  local circuit_name="$(basename "$circuit_path")" && circuit_name="${circuit_name%%.*}"
  local inputs_path="$(dirname "$circuit_path")/${circuit_name}_inputs.json"
  pwd
  if [ ! -f "$inputs_path" ]; then
    echo -e "${RED}Inputs file not found at $inputs_path${NC}"
    exit 1
  fi
  local circuit_bytecode_path="${workdir}/${circuit_name}_bc2.wcd"
  local witness_path="${workdir}/${circuit_name}.wtns"
  local r1cs_path="${workdir}/${circuit_name}.r1cs"
  local sym_path="${workdir}/${circuit_name}.sym"
  local cvm_path="${workdir}/${circuit_name}_cvm/${circuit_name}.cvm"

  pushd "$workdir" > /dev/null

  # Run Circom to generate assembly file.
  circom --r1cs --sym --cvm --wasm "${include_args[@]}" "$circuit_path"

  # run commands from the project directory
  pushd "${script_dir}" > /dev/null

  time target/release/cvm-compile \
    "$cvm_path" "$sym_path" "${circuit_bytecode_path}" \
    --wtns "${witness_path}" --inputs "${inputs_path}" \

  popd > /dev/null

  echo "Generate WASM witness"
  time node "${circuit_name}"_js/generate_witness.js "${circuit_name}"_js/"${circuit_name}".wasm "${inputs_path}" "${witness_path}2"

  snarkjs wej "${witness_path}" "${witness_path}.json"
  snarkjs wej "${witness_path}2" "${witness_path}2.json"

  echo "Check CVM witness"
  snarkjs wtns check "${r1cs_path}" "${witness_path}"
  echo "Check WASM witness"
  snarkjs wtns check "${r1cs_path}" "${witness_path}2"

  if ! cmp -s "${witness_path}" "${witness_path}2"; then
    echo -e "${RED}Witnesses do not match${NC}"
    exit 1
  fi

  popd > /dev/null
}

if [ $# -gt 0 ]; then
  for arg in "$@"; do
    circuit_path=$(realpath "$arg")
    if [ ! -f "$circuit_path" ]; then
      echo -e "${RED}Circuit file not found at $circuit_path${NC}"
      exit 1
    fi
    test_circuit "${circuit_path}"
  done
else
  for circuit_path in "${script_dir}"/test_circuits/*.circom; do
    circuit_path=$(realpath "$circuit_path")
    test_circuit "${circuit_path}"
  done
fi
