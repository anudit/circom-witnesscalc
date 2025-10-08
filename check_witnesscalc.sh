#!/usr/bin/env bash

function check_witnesscalc_graph() {
    local file="$1"
    local directive
    directive=$(grep -m1 '^// witnesscalc:' "$file" | tr -d '\r' || true)

    case "$directive" in
        "// witnesscalc: -graph")
            echo "graph"
            ;;
        "// witnesscalc: -graph -vm")
            echo "graph-vm"
            ;;
        *)
            echo "none"
            ;;
    esac
}
