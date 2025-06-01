#!/usr/bin/env python3
import sys
import json
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
from collections import OrderedDict
import os
from pathlib import Path

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

def get_normalized_types(var_data):
    norm_types = var_data
    
    for type in var_data:
        norm_type = type
        norm_type = norm_type.replace('unsigned ', '')
        norm_type = norm_type.replace('long int', 'long long')
        norm_type = norm_type.strip()
        
        if norm_type != type:
            norm_types.append(norm_type)
    
    return norm_types

def get_location(die,dwarfinfo):
    expr_parser = DWARFExprParser(dwarfinfo.structs)
    loc_attr = die.attributes.get('DW_AT_location')
    if not loc_attr:
        return 0
    ops = expr_parser.parse_expr(loc_attr.value)
    
    offset = 0
    for op in ops:
        if op.op_name == 'DW_OP_fbreg':
            offset = op.args[0]+16

    return offset


def get_array_dims(die, dwarfinfo):
    dims = []
    for sub in die.iter_children():
        if sub.tag == 'DW_TAG_subrange_type':
            lb_attr = sub.attributes.get('DW_AT_lower_bound')
            ub_attr = sub.attributes.get('DW_AT_upper_bound')
            lb = lb_attr.value if lb_attr else 0
            ub = ub_attr.value if ub_attr else None
            count = ub - lb + 1 if ub is not None else None
            dims.append(count)
    
    return dims


def parse_type_die(die,var_data,dwarfinfo):
    try:
        type_attr = die.attributes.get('DW_AT_type')
        type_offset = type_attr.value + die.cu.cu_offset
        type_die = dwarfinfo.get_DIE_from_refaddr(type_offset)

        tag = type_die.tag
        
        # Base types (e.g., int, char)
        if tag == 'DW_TAG_base_type':
            if 'DW_AT_name' in type_die.attributes:
                var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
            var_data['size'] = type_die.attributes['DW_AT_byte_size'].value
            return
        
        #follow typedef
        elif tag == 'DW_TAG_typedef':
            var_data['is_typedef'] = True
            if 'DW_AT_name' in type_die.attributes:
                var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
            parse_type_die(type_die, var_data, dwarfinfo)
            return
        
        # Array types
        elif tag == 'DW_TAG_array_type':
            var_data['is_array'] = True
            parse_type_die(type_die, var_data, dwarfinfo)
            
            array_size = get_array_dims(type_die, dwarfinfo)
            var_data['base_type'] = var_data['type']
            var_data['base_size'] = var_data['size']
            for i in range(len(var_data['type'])):
                var_data['type'][i] += f'[{array_size[0]}]' if array_size else '[]'
            
            var_data['size'] *= array_size[0] 
            return
        
        # Pointer types
        elif tag == 'DW_TAG_pointer_type':
            parse_type_die(type_die,var_data, dwarfinfo)
            
            if var_data['type'] == []:
                var_data['type'].append('void')
            
            for i in range(len(var_data['type'])):
                var_data['type'][i] +=  '*'

            var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value
            return
        
        #constant types
        elif tag == 'DW_TAG_const_type':
            parse_type_die(type_die, var_data, dwarfinfo)
            return

        # Struct/union/class
        elif tag in ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type'):
            var_data['is_struct'] = True
            if 'DW_AT_name' in type_die.attributes:
                var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
            
            if var_data['type'] == []:
                var_data['type'].append('struct')
            var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 8
            return

        # Enum types
        elif tag == 'DW_TAG_enumeration_type':
            if 'DW_AT_name' in type_die.attributes:
                var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
            var_data['type'].append('int')
            var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 4
            return

    except:
        var_data['type'].append('void')


def parse_function_die(die,dwarfinfo):
    func_data = {}

    func_name = die.attributes.get('DW_AT_name').value.decode('utf-8', 'replace')
    address = 0
    if 'DW_AT_low_pc' in die.attributes:
        address = die.attributes.get('DW_AT_low_pc').value
    else:
        address = die.attributes.get('DW_AT_entry_pc').value if 'DW_AT_entry_pc' in die.attributes else 0

    func_data['address'] = hex(address)
    
    func_data['variables'] = []
    for child in die.iter_children():
        if child.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
            var_data = {}
            var_data['name'] = ''
            var_data['RBP offset'] = 0
            var_data['type'] = [] #array to take care of typedef chaining
            var_data['size'] = 0
            var_data['is_typedef'] = False
            var_data['is_struct'] = False
            var_data['is_array'] = False
            
            var_name = child.attributes.get('DW_AT_name').value.decode('utf-8','replace') if 'DW_AT_name' in child.attributes else ''
            var_data['name'] = var_name

            var_data['RBP offset'] = get_location(child,dwarfinfo)
            parse_type_die(child, var_data, dwarfinfo)
            var_data['type'] = get_normalized_types(var_data['type'])
            func_data['variables'].append(var_data)        
    
    return func_name , func_data


def parse_debug(filename):
    functions = {}
    
    elf = ELFFile(open(filename, 'rb'))

    if not elf.has_dwarf_info():
        print('No DWARF info found in the binary.', file=sys.stderr)
        return functions
    
    dwarfinfo = elf.get_dwarf_info()

    for CU in dwarfinfo.iter_CUs():
        cu_offset = CU.cu_offset
        top_DIE = CU.get_top_DIE()
        # Iterate over all compile-unit children
        for DIE in top_DIE.iter_children():
            if DIE.tag != 'DW_TAG_subprogram':
                continue

            func_name,func_data = parse_function_die(DIE, dwarfinfo)

            functions[func_name] = func_data
    return functions

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ELF file>", file=sys.stderr)
        sys.exit(1)
    
    binary_path = Path(sys.argv[1])
    funcs = parse_debug(binary_path)
    funcs = sort_json(funcs)


    output_dir = binary_path
    while output_dir.parent.name != 'binaries':
        output_dir = output_dir.parent
    
    output_dir = output_dir / 'types' / 'ground_truth'
    # print(f"Output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{binary_path.stem}.json"

    with open(output_file, 'w') as outfile:
        json.dump(funcs, outfile, indent=2)

    print(f"Ground truth extracted to {output_file}")

if __name__ == '__main__':
    main()
