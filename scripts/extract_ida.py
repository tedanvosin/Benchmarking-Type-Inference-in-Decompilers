import ida_hexrays
import ida_funcs
import ida_name
import ida_auto
import ida_frame
import idc
import json
import idaapi
import idautils
import ida_typeinf
import ida_nalt
import os
from pathlib import Path

TYPE_MAP = {
        "__int64": "long long",
        "__int32": "int",
        "__int16": "short",
        "__int8": "char",
        "_BOOL8": "bool",
        "_BOOL4": "bool",
        "_BOOL2": "bool",
        "_BOOL1": "bool",
        "_BOOL": "bool",
        "_BYTE": "char",
        "_WORD": "short",
        "_DWORD": "int",
        "_QWORD": "long long",
        "_UNKNOWN": "void"
    }

def normalizetype(var_type):
    var_type = var_type.replace("const ", "")
    var_type = var_type.replace("volatile ", "")
    var_type = var_type.replace("struct ", "")
    var_type = var_type.replace("unsigned ", "")
    var_type = var_type.strip()
    
    for key, value in TYPE_MAP.items():
        if key in var_type:
            var_type = var_type.replace(key, value)
            return var_type
    return var_type

def main():
    if not ida_hexrays.init_hexrays_plugin():
        print("[ERROR] Hex-Rays decompiler is not available.")
        return None

    # Wait for analysis
    ida_auto.auto_wait()
    
    # Get the binary path using IDA API
    binary_path = Path(ida_nalt.get_input_file_path())
    
    output_dir = binary_path
    while output_dir.parent.name != 'binaries':
        output_dir = output_dir.parent
    
    output_dir = output_dir / 'types' / 'ida_types'

    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{binary_path.stem}.json"
    
    # Create a dictionary to store all function data
    all_functions = {}
    
    for func_ea in idautils.Functions():
        # Get the function object
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
            
        # Skip library/thunk functions
        flags = func.flags
        if (flags & ida_funcs.FUNC_LIB) or (flags & ida_funcs.FUNC_THUNK):
            continue
            
        # Skip functions with auto-generated names (likely compiler-generated)
        func_name = ida_funcs.get_func_name(func_ea)
        # if func_name.startswith("sub_") or func_name.startswith("j_") or func_name.startswith("unknown") or func_name.startswith("_"):
        #     continue
            
        # Get frame size
        frame_size = ida_frame.get_frame_size(func_ea)
        frame_lvar_size = idc.get_frame_lvar_size(func_ea)
        # Decompile
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            print(f"Failed to decompile function at {func_ea:#x}")
            continue
            
        # Get variables
        lvars = cfunc.get_lvars()
        
        # Create a temporary list to collect stack variables
        stack_vars = []
        
        # Process each variable
        for lvar in lvars:
            if lvar.is_stk_var():
                var_data = {}
                var_data['name'] = ''
                var_data['RBP offset'] = 0
                var_data['type'] = ''
                var_data['size'] = 0

                var_name = lvar.name
                var_type = str(lvar.type())
                var_type = normalizetype(var_type)
                rsp_offset = lvar.location.stkoff()
                var_location = -frame_lvar_size - (cfunc.get_stkoff_delta() - rsp_offset)
                var_size = lvar.width
                
                var_data['name'] = var_name
                var_data['RBP offset'] = var_location
                var_data['type'] = var_type
                var_data['size'] = var_size

                # Add variable to our temporary list
                stack_vars.append(var_data)
            
        # Function has stack variables, add it to our results
        all_functions[func_name] = {
            "address": f"{func_ea:#x}",
            "variables": stack_vars
        }
    
    # Write the JSON output to file
    with open(output_file, 'w') as outfile:
        json.dump(all_functions, outfile, indent=2)
    
    idaapi.set_database_flag(idaapi.DBFL_KILL)
    
    print(f"JSON output written to {output_file}")
    idc.qexit(0)

if __name__ == "__main__":
    main()