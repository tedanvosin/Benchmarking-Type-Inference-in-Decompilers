#!/usr/bin/env python3
"""
Binary Ninja script to extract stack variables, offsets, and types.
Can be run as a standalone script or from within Binary Ninja.
"""

import json
import os
import sys
from pathlib import Path
import binaryninja

TYPE_MAP = {
    "int64_t": "long long",
    "uint64_t": "unsigned long long",
    "int32_t": "int",
    "uint32_t": "unsigned int",
    "int16_t": "short",
    "uint16_t": "unsigned short",
    "int8_t": "char",
    "uint8_t": "unsigned char",
}

def correct_array_length(var_type):
    base_type = var_type.split('[')[0].strip()
    array_length = var_type.split('[')[1].split(']')[0].strip()
    if array_length.startswith("0x"):
        # Convert hex to decimal
        array_length = str(int(array_length, 16))
        return f"{base_type}[{array_length}]"
    return var_type

def normalize_type(var_type):
    var_type = var_type.replace("const", "")
    var_type = var_type.replace("volatile", "")
    var_type = var_type.replace("struct", "")
    var_type = var_type.strip()
    
    #Correct binja array length representation(hex->decimal)
    if "[" in var_type and "0x" in var_type:
        var_type = correct_array_length(var_type)
    
    for key, value in TYPE_MAP.items():
        if key in var_type:
            var_type = var_type.replace(key, value)
            return var_type
    return var_type

def extract_stack_variables(bv=None,output_file=None):
    all_functions = {}
    
    for function in bv.functions:

        if function.symbol.type == binaryninja.SymbolType.LibraryFunctionSymbol:
            continue
            
        name = function.name
        if name.startswith("sub_") or name.startswith("__"):
            continue
            
        stack_vars = []
        
        for var in function.vars:
            if var.source_type == binaryninja.VariableSourceType.StackVariableSourceType:
                var_data = {}
                var_data['name'] = ''
                var_data['RBP offset'] = 0
                var_data['type'] = ''
                var_data['size'] = 0
                
                var_name = var.name
                
                var_type = str(var.type)
                var_type = normalize_type(var_type)
                
                offset = var.storage
                offset += 8
                if offset>=0:
                    continue

                var_location = offset
                var_size = var.type.width

                var_data['name'] = var_name
                var_data['RBP offset'] = var_location
                var_data['type'] = var_type
                var_data['size'] = var_size

                stack_vars.append(var_data)
            
        all_functions[name] = {
            "address": hex(function.start),
            "variables": stack_vars
        }
    
    with open(output_file, 'w') as f:
        json.dump(all_functions, f, indent=2)
    
    print(f"Stack variable information written to {output_file}")
    return all_functions

def standalone_main():
    
    binary_path = Path(sys.argv[1])
    
    output_dir = binary_path
    while output_dir.parent.name != 'binaries':
        output_dir = output_dir.parent
    
    output_dir = output_dir / 'types' / 'binja_types'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{binary_path.stem}.json"
    
    print(f"Loading binary: {binary_path}")
    try:
        # Try the correct method for Binary Ninja version >= 2.2
        bv = binaryninja.load(binary_path)
    except AttributeError:
        # Fallback for older versions
        bv = binaryninja.BinaryViewType.get_view_of_file(binary_path)
    
    print("Waiting for analysis to complete...")
    bv.update_analysis_and_wait()
    
    extract_stack_variables(bv, output_file)
    
    bv.file.close()


if __name__ == "__main__":
    standalone_main()
