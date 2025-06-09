import angr
import logging
from pathlib import Path
import json
import sys
from collections import OrderedDict

# Disable some of the more verbose logging
for name in ('angr', 'cle', 'pyvex'):
    logging.getLogger(name).setLevel(logging.CRITICAL)

def sort_json(data):
    ordered = OrderedDict(
        sorted(
            data.items(),
            key=lambda item: int(item[1]['address'], 16)
        )
    )
    # 2. Sort each function’s variables by RBP offset
    for func, info in ordered.items():
        info['variables'] = sorted(
            info.get('variables', []),
            key=lambda var: var['RBP offset']
        )
    return ordered

def normalize_type(var_type):
    var_type = var_type.replace("const", "")
    var_type = var_type.replace("volatile", "")
    var_type = var_type.replace("unsigned ","")
    var_type = var_type.replace("signed", "")
    var_type = var_type.replace("int(32bits)", "int")
    var_type = var_type.replace("int(64bits)", "long long")
    var_type = var_type.replace("int(16bits)", "short")
    var_type = var_type.replace("int(8bits)", "char")
    var_type = var_type.strip()
    if var_type == "long":
        var_type = "long long"

    return var_type

def analyze_binary(binary_path):

    output_dir = binary_path
    while output_dir.parent.name != 'binaries':
        output_dir = output_dir.parent
    
    output_dir = output_dir / 'types' / 'angr_types'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{binary_path.stem}.json"

    project = angr.Project(binary_path, auto_load_libs=False)

    CFG = project.analyses.CFG(normalize=True,data_references=True)
    project.analyses.CompleteCallingConventions(cfg=CFG,recover_variables=True)

    all_functions = {}

    for func_addr,func in project.kb.functions.items():
        if func.is_plt or func.is_simprocedure or func.is_syscall:
            continue

        if func.size:
            # Run the decompiler
            decompilation = project.analyses.Decompiler(func, cfg=CFG)

            code_gen = decompilation.codegen
            
            #angr could not decompile
            if not code_gen:
                continue
            
            stack_vars = []
            for var in code_gen.cfunc.variable_manager._unified_variables:
                if hasattr(var, 'offset') and var.offset<0:
                    var_data = {}
                    var_data['name'] = ''
                    var_data['RBP offset'] = 0
                    var_data['type'] = ''
                    var_data['size'] = 0
                    
                    var_name = var.name
                    var_type = code_gen.cfunc.variable_manager.get_variable_type(var).c_repr()
                    var_type = normalize_type(var_type)
                    var_size = var.size
                    var_location = var.offset+8
                    
                    var_data['name'] = var_name
                    var_data['RBP offset'] = var_location
                    var_data['type'] = var_type
                    var_data['size'] = var_size

                    # Add variable to our temporary list
                    stack_vars.append(var_data)

            # Function has stack variables, add it to our results
            all_functions[func.name] = {
                "address": f"{func_addr:#x}",
                "variables": stack_vars
            }
    
    all_functions = sort_json(all_functions)
    # Write the JSON output to file
    with open(output_file, 'w') as outfile:
        json.dump(all_functions, outfile, indent=2)
    print(f"Analysis complete. Output written to {output_file}")

if __name__ == "__main__":
    binary_path = Path(sys.argv[1])
    analyze_binary(binary_path)
