#!/bin/bash -l

# Note: If conda activate doesn't work, you may need to adjust the conda initialization path
# or use: source ~/miniconda3/etc/profile.d/conda.sh (adjust path as needed)

if [ $# -ne 3 ]; then
    echo "Usage: $0 <tool> <base_dir> <n>"
    echo "Tools: retypd, ida, gt, ghidra, binja, angr, all"
    echo "Base Dirs: O0/O1/O2/O3"
    echo "N: Number of files to process (0 for all)"
    exit 1
fi

TOOL=$1

THESIS_DIR="$PWD"
BASE_DIR="$THESIS_DIR/binaries/$2"
N=$3
FILE_LIST="$BASE_DIR/file_list.txt"

source "$HOME/anaconda3/etc/profile.d/conda.sh"
conda activate base

if [ ! -f "$FILE_LIST" ]; then
    echo "Error: file_list.txt not found in $BASE_DIR"
    exit 1
fi

process_files() {
    local bin_type=$1
    local cmd=$2
    
    i=0
    while IFS= read -r relpath && [ $i -lt $N ]; do
        [ -z "$relpath" ] && continue
        
        bin_path="$BASE_DIR/$bin_type/$relpath"
        if [ ! -f "$bin_path" ]; then
            echo "  → Skipping (not found): $bin_path" >&2
            continue
        fi
        
        echo "Running: $cmd"
        eval "$cmd"
        ((i++))
    done < "$FILE_LIST"
}

run_retypd() {
    conda activate retypd
    GHIDRA="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    process_files "binaries_stripped" "$GHIDRA /tmp tmp_proj -import \$bin_path -overwrite -preScript Retypd.java -postScript extract_retypd.py -scriptPath '$THESIS_DIR/scripts;$THESIS_DIR/Decompilers/retypd/GhidraRetypd/ghidra_scripts'"
    conda deactivate
}

run_ida() {
    process_files "binaries_stripped" "idat64 -A -Sscripts/extract_ida.py \$bin_path"
}

run_gt() {
    process_files "binaries_debug" "python scripts/extract_gt.py \$bin_path"
}

run_ghidra() {
    GHIDRA="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
    process_files "binaries_stripped" "$GHIDRA /tmp tmp_proj -import \$bin_path -overwrite -postScript extract_ghidra.py -scriptPath $THESIS_DIR/scripts"
}

run_binja() {
    process_files "binaries_stripped" "python scripts/extract_binja.py \$bin_path"
}

run_angr() {
    process_files "binaries_stripped" "python scripts/extract_angr.py \$bin_path"
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