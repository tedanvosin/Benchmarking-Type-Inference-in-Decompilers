import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.app.script import GhidraScript
from collections import OrderedDict

TYPE_MAP = {
        "undefined *": "void *",
        "undefined8": "long long",
        "undefined4": "int",
        "undefined2": "short",
        "undefined1": "char",
        "undefined": "char",
        "uint": "int",
        "ulong": "long long",
        "ushort": "short",
        "uchar": "char",
        "char8": "char[8]",
        "char4": "char[4]",
        "char2": "char[2]",
        "char1": "char",
        "sbyte": "char",
        "byte": "char",
}

def sort_json(data):
    ordered = OrderedDict(
        sorted(
            data.items(),
            key=lambda item: int(item[1]['address'], 16)
        )
    )
    for func, info in ordered.items():
        info['variables'] = sorted(
            info.get('variables', []),
            key=lambda var: var['RBP offset']
        )
    return ordered

def normalize_type(var_type):
    if var_type == 'long':
        var_type = 'long long'
    
    var_type = var_type.replace("const", "")
    var_type = var_type.replace("volatile", "")
    var_type = var_type.replace("unsigned", "")
    var_type = var_type.replace("signed", "")
    var_type = var_type.strip()
    for key, value in TYPE_MAP.items():
        if key in var_type:
            var_type = var_type.replace(key, value)
            
            return var_type
    return var_type


def run_custom_type_plugin():
    """Run your custom plugin to modify types"""
    try:
        runScript("Retypd.java")
        
        
        print("Custom type modification completed successfully")
    except Exception as e:
        print("Error running custom type plugin: %s" % str(e))


def get_stack_variables():
    """Extract stack variables after type modification"""
    # Create output directory structure
    program_name = currentProgram.getName()
    binary_path = currentProgram.getExecutablePath()

    output_dir = binary_path
    while os.path.basename(os.path.dirname(output_dir)) != 'binaries':
        output_dir = os.path.dirname(output_dir)

    
    output_dir = os.path.join(output_dir, 'types', 'retypd_types')

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    
    output_file = output_dir + '/'+program_name + ".json"
    
    # Setup decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    # Get function manager
    function_manager = currentProgram.getFunctionManager()
    all_functions = OrderedDict()
    
    # Iterate through all functions
    for function in function_manager.getFunctions(True):
        # Skip library functions, thunks, and external functions
        if function.isThunk() or function.isExternal():
            continue
            
        if function.getName().startswith("FUN_") or function.getName().startswith("__"):
            continue
        
        function_name = function.getName()
        function_addr = function.getEntryPoint().getOffset()
        
        # Get decompiled function
        results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            continue
        
        high_func = results.getHighFunction()
        if high_func is None:
            continue
        
        # Get local variables (stack variables)
        lsm = high_func.getLocalSymbolMap()
        if lsm is None:
            continue
        
        stack_vars = []
        # Iterate through all symbols in the local symbol map
        for symbol in lsm.getSymbols():
            # Check if it's a stack variable by examining its storage
            storage = symbol.getStorage()
            if storage is not None and storage.isStackStorage():
                var_data = OrderedDict()
                var_data['name'] = ''
                var_data['RBP offset'] = 0
                var_data['type'] = ''
                var_data['size'] = 0
                
                var_name = symbol.getName()
                var_type = "unknown"
                try:
                    data_type = symbol.getDataType()
                    if data_type is not None:
                        var_type = data_type.getDisplayName()
                        var_size = data_type.getLength()
                except:
                    pass
                
                var_offset = storage.getStackOffset()
                var_offset += 8
                var_location = var_offset

                var_type = normalize_type(var_type)

                var_data['name'] = var_name
                var_data['RBP offset'] = var_location
                var_data['type'] = var_type
                var_data['size'] = var_size

                stack_vars.append(var_data)
            
        all_functions[function_name] = {
            "address": hex(function_addr)[:-1],  # Remove the 'L' suffix
            "variables": stack_vars
        }
    
    all_functions = sort_json(all_functions)

    # Write output to JSON file
    with open(output_file, 'w+') as f:
        json.dump(all_functions, f, indent=2)
    
    print("Stack variable information written to %s" % output_file)

# Run both steps
try:
    print("Step 1: Running type modification plugin...")
    run_custom_type_plugin()
    
    print("Step 2: Extracting stack variables...")
    get_stack_variables()
    
    print("Script completed successfully")
except Exception as e:
    print("Error running script: %s" % str(e))