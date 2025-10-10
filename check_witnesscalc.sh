#!/usr/bin/env bash

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Return 0 if the circuit file passed as $1 is supported by the vm of type $2.
# To determine if file is supported, we are looking for occurrences of the
# `//\s*witnesscalc:enabled <tags>` lines.
# Tags could be in the form `vm_type` or `!vm_type` which means inclusion
# or exclusion the appropriate vm type.
# By default if no tags are found, then the file is enabled.
# If we found inclution tags, that means the circuit is only enabled for those
# vm types. If there are exclusion tags, those means the circuit is not
# supported by those types but is supported by everything else if there are no
# inclusion tags. If there are both inclusion and exclusion tags, then the
# circuit file is supported only by inclusion tags if only there is no
# corresponding exclusion tag.
# Currently supported vm types are:
#   - graph
#   - vm
#   - vm2
# Examples.
#  //witnesscalc:enabled vm vm2  -> enabled only for vm and vm2
#  //witnesscalc:enabled !graph  -> enabled everywhere except graph
#  //witnesscalc:enabled vm !vm2  -> enabled only for vm
#  //witnesscalc:enabled vm vm2 !vm2  -> enabled only for vm
function circuit_is_enabled() {
	local file="$1"
	local vm_type="$2"

	local directive
	directive=$(grep -m1 '^\s*//\s*witnesscalc:enabled' "$file" | tr -d '\r' || true)

	if [ -z "$directive" ]; then
		return 0
	fi

	local tags="${directive#*witnesscalc:enabled}"
	tags=$(echo "$tags" | xargs)

	local has_inclusion=0
	local has_exclusion=0
	local is_included=0
	local is_excluded=0

	for tag in $tags; do
		if [[ "$tag" == !* ]]; then
			has_exclusion=1
			local excluded_vm="${tag#!}"
			if [ "$excluded_vm" = "$vm_type" ]; then
				is_excluded=1
			fi
		else
			has_inclusion=1
			if [ "$tag" = "$vm_type" ]; then
				is_included=1
			fi
		fi
	done

	if [ $has_inclusion -eq 1 ]; then
		if [ $is_included -eq 1 ] && [ $is_excluded -eq 0 ]; then
			return 0
		else
			return 1
		fi
	elif [ $has_exclusion -eq 1 ]; then
		if [ $is_excluded -eq 1 ]; then
			return 1
		else
			return 0
		fi
	fi

	return 0
}
