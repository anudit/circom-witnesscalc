#!/usr/bin/env bash

set -eu

ptau_url="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau"

required_commands=(circom snarkjs curl cargo node cmp)

RED='\033[0;31m'
NC='\033[0m' # No Color

for cmd in "${required_commands[@]}"; do
	if ! command -v "$cmd" &> /dev/null; then
		echo -e "${RED}\`$cmd\` command could not be found${NC}"
		exit 1
	fi
done

workdir="$(pwd)/test_working_dir"

if [ ! -d "$workdir" ]; then
	echo "Creating working directory $workdir"
	mkdir "$workdir"
fi

ptau_path="${workdir}/$(basename $ptau_url)"

print_usage() {
    echo "Usage: $0 [-p <ptau_file_path>] [-h] [-l <inlcude_path>] [file1 ...]"
    echo
    echo "Options:"
    echo "  -p <ptau_file_path>    Path to ptau file (if provided multiple times, last one is used)"
    echo "                         If omitted, the default file will be downloaded from:"
    echo "                         ${ptau_url}"
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
    p)
        ptau_path="$OPTARG"
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

if [ ! -f "$ptau_path" ]; then
	echo "Downloading $ptau_url to $ptau_path"
	curl -L "$ptau_url" -o "$ptau_path"
fi

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
cargo build --release --workspace
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
	local circuit_graph_path="${workdir}/${circuit_name}_graph.wcd"
	local witness_path="${workdir}/${circuit_name}.wtns"
	local proof_path="${workdir}/${circuit_name}_proof.json"
	local public_signals_path="${workdir}/${circuit_name}_public.json"
	local r1cs_path="${workdir}/${circuit_name}.r1cs"

	# run commands from the project directory
	pushd "${script_dir}" > /dev/null
	time target/release/build-circuit "$circuit_path" "$circuit_graph_path" "${include_args[@]}"
	time target/release/calc-witness "$circuit_graph_path" "$inputs_path" "$witness_path"
	popd > /dev/null

	# run commands from the working directory
	pushd "$workdir" > /dev/null

#	circom "${include_args[@]}" --prime grumpkin --r1cs --wasm "$circuit_path"
	circom "${include_args[@]}" --r1cs --wasm "$circuit_path"
	local r1cs_md5=$(openssl dgst -hex -md5 "${r1cs_path}" | awk '{print $2}')
	local zkey_path="${circuit_name}_${r1cs_md5}_final.zkey"
	local vk_path="${workdir}/${circuit_name}_${r1cs_md5}_verification_key.json"

	time node "${circuit_name}"_js/generate_witness.js "${circuit_name}"_js/"${circuit_name}".wasm "${inputs_path}" "${witness_path}2"
	snarkjs wej "${witness_path}" "${witness_path}.json"
	snarkjs wej "${witness_path}2" "${witness_path}2.json"

	snarkjs wtns check "${r1cs_path}" "${witness_path}"
	snarkjs wtns check "${r1cs_path}" "${witness_path}2"
	if ! cmp -s "${witness_path}" "${witness_path}2"; then
		echo -e "${RED}Witnesses do not match${NC}"
		exit 1
	fi

	if [ ! -f "$zkey_path" ]; then
		snarkjs groth16 setup "${r1cs_path}" "$ptau_path" "${circuit_name}"_"${r1cs_md5}"_0000.zkey
		local ENTROPY1=$(head -c 64 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
		snarkjs zkey contribute "${circuit_name}"_"${r1cs_md5}"_0000.zkey "${zkey_path}" --name="1st Contribution" -v -e="$ENTROPY1"
		snarkjs zkey verify "${r1cs_path}" "$ptau_path" "${zkey_path}"
	fi
	if [ ! -f "$vk_path" ]; then
		snarkjs zkey export verificationkey "${zkey_path}" "${vk_path}"
	fi
	# export witness as text ints
	# snarkjs wej witness.wtns witness.json

	snarkjs groth16 prove "${zkey_path}" "${witness_path}" "${proof_path}" "${public_signals_path}"
	snarkjs groth16 verify "${vk_path}" "${public_signals_path}" "${proof_path}"

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
