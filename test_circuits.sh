#!/usr/bin/env bash

set -eu

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/check_witnesscalc.sh"

ptau_url="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_18.ptau"

required_commands=(circom curl cargo node cmp)

TEST_TAG="graph"

for cmd in "${required_commands[@]}"; do
	if ! command -v "$cmd" &>/dev/null; then
		echo -e "${RED}\`$cmd\` command could not be found${NC}"
		exit 1
	fi
done

if command -v snarkjs &>/dev/null; then
	SNARKJS=snarkjs
elif command -v npx &>/dev/null; then
	SNARKJS="npx snarkjs"
	echo "Using npx snarkjs"
else
	echo -e "${RED}\`snarkjs\` not found in PATH and npx is not available${NC}"
	exit 1
fi

workdir="$(pwd)/test_working_dir"

if [ ! -d "$workdir" ]; then
	echo "Creating working directory $workdir"
	mkdir "$workdir"
fi

ptau_path="${workdir}/$(basename $ptau_url)"

print_usage() {
	echo "Usage: $0 [-p <ptau_file_path>] [-b <build_circuit_path>] [-t <tag>] [-h] [-l <inlcude_path>] [-i <inputs_path>] [file1 ...]"
	echo
	echo "Options:"
	echo "  -p <ptau_file_path>    Path to ptau file (if provided multiple times, last one is used)"
	echo "                         If omitted, the default file will be downloaded from:"
	echo "                         ${ptau_url}"
	echo "  -b <build_circuit>     Path to build-circuit binary (default: target/release/build-circuit)"
	echo "  -t <tag>               Test tag for filtering circuits (default: graph)"
	echo "  -l <include_path>      Path to include directory. Can be specified multiple times"
	echo "  -i <inputs_path>       Path to custom inputs JSON file. Requires exactly one circuit file argument"
	echo "  -h                     Print this usage and exit"
	echo
	echo "Positional Arguments:"
	echo "  file1       Circom circuit file. May be multiple. If none provided, all circuits in test_circuits/ directory processed."
	echo
	echo "Examples:"
	echo "  $0 test_circuits/circuit1.circom"
	echo "  $0 -i custom_inputs.json test_circuits/circuit1.circom"
}

declare -a library_paths=()
build_circuit_path=""
custom_inputs_path=""

while getopts ":p:l:b:t:i:h" opt; do
	case $opt in
	h)
		print_usage
		exit 0
		;;
	p)
		ptau_path="$OPTARG"
		;;
	b)
		build_circuit_path="$OPTARG"
		;;
	t)
		TEST_TAG="$OPTARG"
		;;
	l)
		library_paths+=("$OPTARG")
		;;
	i)
		custom_inputs_path="$OPTARG"
		;;
	:)
		echo "Error: -$OPTARG requires a value" >&2
		exit 1
		;;
	\?)
		echo "Error: Invalid option -$OPTARG" >&2
		exit 1
		;;
	esac
done

# Shift past the named options to access positional arguments
shift $((OPTIND - 1))

if [ -n "$custom_inputs_path" ]; then
	if [ $# -ne 1 ]; then
		echo "Error: -i option requires exactly one circuit file argument" >&2
		echo "Found $# circuit file argument(s)" >&2
		print_usage
		exit 1
	fi
	if [ ! -f "$custom_inputs_path" ]; then
		echo "Error: Custom inputs file not found at $custom_inputs_path" >&2
		exit 1
	fi
	custom_inputs_path="$(realpath "$custom_inputs_path")"
fi

if [ -z "$TEST_TAG" ]; then
	echo "Error: test tag cannot be empty" >&2
	exit 1
fi

if [ ! -f "$ptau_path" ]; then
	echo "Downloading $ptau_url to $ptau_path"
	curl -L "$ptau_url" -o "$ptau_path"
fi

if [ ${#library_paths[@]} -eq 0 ]; then
	library_paths+=("${script_dir}/test_deps/circomlib/circuits")
fi

if [ -z "$build_circuit_path" ]; then
	build_circuit_path="${script_dir}/target/release/build-circuit"
fi

declare -a include_args

for arg in "${library_paths[@]}"; do
	if [ ! -d "$arg" ]; then
		echo -e "${RED}include path not found at $arg${NC}"
		exit 1
	fi
	include_args+=("-l" "$arg")
done

pushd "${script_dir}" >/dev/null
cargo build --release --workspace
popd >/dev/null

function test_circuit() {
	local circuit_path=$1
	local custom_inputs=$2
	echo "Running $circuit_path"
	local circuit_name
	circuit_name="$(basename "$circuit_path")" && circuit_name="${circuit_name%%.*}"
	local inputs_path
	if [ -n "$custom_inputs" ]; then
		inputs_path="$custom_inputs"
	else
		inputs_path="$(dirname "$circuit_path")/${circuit_name}_inputs.json"
	fi
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
	pushd "${script_dir}" >/dev/null
	time "$build_circuit_path" "$circuit_path" "$circuit_graph_path" "${include_args[@]}"
	time target/release/calc-witness "$circuit_graph_path" "$inputs_path" "$witness_path"
	popd >/dev/null

	# run commands from the working directory
	pushd "$workdir" >/dev/null

	#	circom "${include_args[@]}" --prime grumpkin --r1cs --wasm "$circuit_path"
	time circom "${include_args[@]}" --O2 --sym --r1cs --wasm "$circuit_path"
	local r1cs_md5
	r1cs_md5=$(openssl dgst -hex -md5 "${r1cs_path}" | awk '{print $2}')
	local zkey_path="${circuit_name}_${r1cs_md5}_final.zkey"
	local vk_path="${workdir}/${circuit_name}_${r1cs_md5}_verification_key.json"

	time node "${circuit_name}"_js/generate_witness.js "${circuit_name}"_js/"${circuit_name}".wasm "${inputs_path}" "${witness_path}2"
	$SNARKJS wej "${witness_path}" "${witness_path}.json"
	$SNARKJS wej "${witness_path}2" "${witness_path}2.json"

	$SNARKJS wtns check "${r1cs_path}" "${witness_path}"
	$SNARKJS wtns check "${r1cs_path}" "${witness_path}2"
	if ! cmp -s "${witness_path}" "${witness_path}2"; then
		echo -e "${RED}Witnesses do not match${NC}"
		exit 1
	fi

	if [ ! -f "$zkey_path" ]; then
		$SNARKJS groth16 setup "${r1cs_path}" "$ptau_path" "${circuit_name}"_"${r1cs_md5}"_0000.zkey
		local ENTROPY1
		ENTROPY1=$(head -c 64 /dev/urandom | od -An -tx1 -v | tr -d ' \n')
		$SNARKJS zkey contribute "${circuit_name}"_"${r1cs_md5}"_0000.zkey "${zkey_path}" --name="1st Contribution" -v -e="$ENTROPY1"
		$SNARKJS zkey verify "${r1cs_path}" "$ptau_path" "${zkey_path}"
	fi
	if [ ! -f "$vk_path" ]; then
		$SNARKJS zkey export verificationkey "${zkey_path}" "${vk_path}"
	fi
	# export witness as text ints
	# snarkjs wej witness.wtns witness.json

	$SNARKJS groth16 prove "${zkey_path}" "${witness_path}" "${proof_path}" "${public_signals_path}"
	$SNARKJS groth16 verify "${vk_path}" "${public_signals_path}" "${proof_path}"

	popd >/dev/null
}

if [ $# -gt 0 ]; then
	for arg in "$@"; do
		circuit_path=$(realpath "$arg")
		if [ ! -f "$circuit_path" ]; then
			echo -e "${RED}Circuit file not found at $circuit_path${NC}"
			exit 1
		fi
		test_circuit "${circuit_path}" "$custom_inputs_path"
	done
else
	for circuit_path in "${script_dir}"/test_circuits/*.circom; do
		circuit_path=$(realpath "$circuit_path")

		if ! circuit_is_enabled "$circuit_path" "${TEST_TAG}"; then
			echo -e "${YELLOW}Skipped $circuit_path (not enabled for ${TEST_TAG})${NC}"
			continue
		fi

		test_circuit "${circuit_path}" ""
	done
fi
