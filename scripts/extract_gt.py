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
    for func, info in ordered.items():
        info['variables'] = sorted(
            info.get('variables', []),
            key=lambda var: var['RBP offset']
        )
    return ordered

def get_normalized_types(var_data):
    norm_types = var_data[:]
    
    for type in var_data:
        norm_type = type
        norm_type = norm_type.replace('unsigned ', '')
        norm_type = norm_type.replace('long long int', 'long long')
        norm_type = norm_type.replace('long int', 'long long')
        norm_type = norm_type.replace('_Bool', 'bool')
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
    try:
        dims = []
        for sub in die.iter_children():
            if sub.tag == 'DW_TAG_subrange_type':
                lb_attr = sub.attributes.get('DW_AT_lower_bound')
                ub_attr = sub.attributes.get('DW_AT_upper_bound')
                lb = lb_attr.value if lb_attr else 0
                ub = ub_attr.value if ub_attr else None
                count = ub - lb + 1 if ub is not None else None
                dims.append(count)
    except:
        dims = []    
    return dims

def parse_struct(die, var_data, dwarfinfo):
    type_attr = die.attributes.get('DW_AT_type')
    type_offset = type_attr.value + die.cu.cu_offset
    type_die = dwarfinfo.get_DIE_from_refaddr(type_offset)

    tag = type_die.tag
    
    if tag == 'DW_TAG_typedef':
        parse_struct(type_die, var_data, dwarfinfo)
        return

    base_offset = var_data['RBP offset']
    for child in type_die.iter_children():
        if child.tag == 'DW_TAG_member':
            member_data = {}
            member_data['name'] = var_data['name']+'.'+child.attributes.get('DW_AT_name').value.decode('utf-8', 'replace') if 'DW_AT_name' in child.attributes else ''
            member_data['RBP offset'] = base_offset + child.attributes.get('DW_AT_data_member_location').value
            member_data['type'] = []
            member_data['size'] = 0
            member_data['is_pointer'] = False
            member_data['is_typedef'] = False
            member_data['is_array'] = False
            member_data['is_struct'] = False
            parse_type_die(child, member_data, dwarfinfo)
            member_data['type'] = get_normalized_types(member_data['type'])
            
            if member_data['is_array']:
                member_data['element_type'] = get_normalized_types(member_data['element_type'])
            
            var_data['elements'].append(member_data)
    
    return


def parse_type_die(die,var_data,dwarfinfo):
    if 'DW_AT_type' not in die.attributes:
        var_data['type'].append('void')
        return
    
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
        
        var_data['array_length'] = array_size[0] if array_size else 1
        var_data['element_type'] = var_data['type'][:]
        var_data['element_size'] = var_data['size']
        
        for i in range(len(var_data['type'])):
            var_data['type'][i] += f'[{array_size[0]}]' if array_size else '[]'

        if len(array_size):
            var_data['size'] *= array_size[0] 
        return
    
    # Pointer types
    elif tag == 'DW_TAG_pointer_type':
        var_data['is_pointer'] = True
        parse_type_die(type_die,var_data, dwarfinfo)
        
        if var_data['type'] == []:
            var_data['type'].append('void')
        
        for i in range(len(var_data['type'])):
            var_data['type'][i] +=  '*'

        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value
        return
    
    #constant types
    elif tag == 'DW_TAG_const_type' or tag == 'DW_TAG_volatile_type':
        parse_type_die(type_die, var_data, dwarfinfo)
        return

    # Struct types
    elif tag =='DW_TAG_structure_type':
        var_data['is_struct'] = True
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        
        if var_data['type'] == []:
            var_data['type'].append('struct')
        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 8
        
        return
    
    #union/class
    elif tag in ('DW_TAG_union_type', 'DW_TAG_class_type'):
        var_data['is_union'] = True
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
    
    else:
        return


def parse_variable_die(child_die, dwarfinfo):
    var_data = {}
    var_data['name'] = ''
    var_data['RBP offset'] = 0
    var_data['type'] = [] #array to take care of typedef chaining
    var_data['size'] = 0
    var_data['is_pointer'] = False
    var_data['is_typedef'] = False
    var_data['is_array'] = False
    var_data['is_struct'] = False
    var_data['is_union'] = False
    
    var_name = child_die.attributes.get('DW_AT_name').value.decode('utf-8','replace') if 'DW_AT_name' in child_die.attributes else ''
    var_data['name'] = var_name

    var_data['RBP offset'] = get_location(child_die,dwarfinfo)

    parse_type_die(child_die, var_data, dwarfinfo)
    var_data['type'] = get_normalized_types(var_data['type'])

    if not var_data['is_pointer'] and var_data['is_array']:
        var_data['element_type'] = get_normalized_types(var_data['element_type'])
    
    if not var_data['is_pointer'] and var_data['is_struct']:
        var_data['elements'] = []
        parse_struct(child_die, var_data, dwarfinfo)
    
    return var_data


def parse_lexical_block(die, dwarfinfo):
    variables = []
    
    for child in die.iter_children():
        if child.tag == 'DW_TAG_lexical_block':
            lex_variables = parse_lexical_block(child, dwarfinfo)
            variables.extend(lex_variables)
        
        elif child.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
            var_data = parse_variable_die(child, dwarfinfo)
            variables.append(var_data)
    
    return variables
            


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
        
        if child.tag == 'DW_TAG_lexical_block':
            lex_variables = parse_lexical_block(child, dwarfinfo)
            func_data['variables'].extend(lex_variables)
        
        elif child.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
            var_data = parse_variable_die(child, dwarfinfo)
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
    output_dir = binary_path
    while output_dir.parent.name != 'binaries':
        output_dir = output_dir.parent
    
    output_dir = output_dir / 'types' / 'ground_truth'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{binary_path.stem}.json"
    
    funcs = parse_debug(binary_path)
    funcs = sort_json(funcs)

    with open(output_file, 'w') as outfile:
        json.dump(funcs, outfile, indent=2)

    print(f"Ground truth extracted to {output_file}")

if __name__ == '__main__':
    main()
