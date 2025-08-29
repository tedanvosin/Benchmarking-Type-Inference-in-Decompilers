#!/bin/bash -l

if [ $# -ne 3 ]; then
    echo "Usage: $0 <tool> <base_dir> <binary_name>"
    echo "Tools: retypd, ida, gt, ghidra, binja, angr, all"
    echo "Base Dirs: O0 (to be extended)"
    echo "Binary Name: Name of binary file (relative to binaries_stripped/debug)"
    exit 1
fi

TOOL=$1
PROJ_DIR="$PWD"
BASE_DIR="$PROJ_DIR/binaries/$2"
BINARY_NAME=$3

process_file() {
    local bin_type=$1
    local cmd=$2

    bin_path="$BASE_DIR/$bin_type/$BINARY_NAME"
    tmp_proj="tmp_proj"

    if [ ! -f "$bin_path" ]; then
        echo "Error: binary not found: $bin_path"
        exit 1
    fi

    echo "Processing: $bin_path"
    eval "$cmd"
}

run_retypd() {
    GHIDRA="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    process_file "binaries_stripped" \
        "$GHIDRA /tmp \$tmp_proj \
        -import \$bin_path \
        -overwrite \
        -preScript Retypd.java \
        -postScript extract_retypd.py \
        -scriptPath '$PROJ_DIR/scripts;$GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraRetypd/ghidra_scripts' \
        -deleteProject" # \
        #-log /dev/null > /dev/null 2>&1"
}

run_ida() {
    process_file "binaries_stripped" "idat64 -A -Sscripts/extract_ida.py \$bin_path"
}

run_gt() {
    process_file "binaries_debug" "python scripts/extract_gt.py \$bin_path"
}

run_ghidra() {
    GHIDRA="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    process_file "binaries_stripped" \
        "$GHIDRA /tmp \$tmp_proj \
        -import \$bin_path \
        -overwrite \
        -postScript extract_ghidra.py \
        -scriptPath $PROJ_DIR/scripts \
        -deleteProject \
        -log /dev/null > /dev/null 2>&1"
}

run_binja() {
    process_file "binaries_stripped" "python scripts/extract_binja.py \$bin_path"
}

run_angr() {
    process_file "binaries_stripped" "python scripts/extract_angr.py \$bin_path"
}

run_all() {
    for tool in gt angr binja ghidra ida retypd; do
        echo "=== Processing with $tool ==="
        run_$tool
    done
}

if type "run_$TOOL" &> /dev/null; then
    run_$TOOL
else
    echo "Unknown tool: $TOOL"
    echo "Valid tools: retypd, ida, gt, ghidra, binja, angr, all"
    exit 1
fi
