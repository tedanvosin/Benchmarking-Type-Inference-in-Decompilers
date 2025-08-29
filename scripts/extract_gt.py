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
            # key=lambda item: int(item[1]['address'], 16)
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
        norm_type = norm_type.replace("signed ", "")
        norm_type = norm_type.replace('long long int', 'long long')
        norm_type = norm_type.replace('long int', 'long long')
        norm_type = norm_type.replace('_Bool', 'bool')
        norm_type = norm_type.replace('Bool', 'bool')
        norm_type = norm_type.replace('boolean', 'bool')
        norm_type = norm_type.strip()
        
        if norm_type != type:
            norm_types.append(norm_type)
    
    return norm_types

def get_location(die,dwarfinfo):
    offset = []
    
    if 'DW_AT_location' not in die.attributes:
        return offset

    loc_attr = die.attributes.get('DW_AT_location')
    expr_parser = DWARFExprParser(dwarfinfo.structs)
    loclists = dwarfinfo.location_lists()

    if loc_attr.form == 'DW_FORM_exprloc':
        ops = expr_parser.parse_expr(loc_attr.value)
        for op in ops:
            if op.op_name == 'DW_OP_fbreg':
                offset.append(op.args[0]+16)
    
    elif loc_attr.form == 'DW_FORM_sec_offset':
        loclist = loclists.get_location_list_at_offset(loc_attr.value,die=die)

        for entry in loclist:
            expr = getattr(entry, 'loc_expr', None) or getattr(entry, 'location_expr', None)
            if expr is None:
                continue
            ops = expr_parser.parse_expr(expr)
            
            if len(ops)!=1:
                continue
            
            for op in ops:
                if op.op_name == 'DW_OP_fbreg':
                    offset.append(op.args[0]+16)

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

            if 'DW_AT_data_member_location' not in child.attributes:
                continue

            member_data['RBP offset'] = base_offset + child.attributes.get('DW_AT_data_member_location').value
            member_data['type'] = []
            member_data['size'] = 0
            member_data['is_pointer'] = False
            member_data['is_typedef'] = False
            member_data['is_array'] = False
            member_data['is_struct'] = False
            member_data['is_union'] = False
            member_data['is_enum'] = False

            parse_type_die(child, member_data, dwarfinfo)
            member_data['type'] = get_normalized_types(member_data['type'])
            member_data['type'] = set(member_data['type'])  # Remove duplicates
            member_data['type'] = list(member_data['type'])  # Convert back to list
            
            if member_data['is_array']:
                member_data['element_type'] = get_normalized_types(member_data['element_type'])
            
            if member_data['is_struct']:
                member_data['elements'] = []
                parse_struct(child, member_data, dwarfinfo)
            
            var_data['elements'].append(member_data)
    
    return

def get_DIE_by_reference(die, attr_name: str, dwarfinfo):
    attr = die.attributes[attr_name]
    assert attr.form == "DW_FORM_ref4"
    return dwarfinfo.get_DIE_from_refaddr(attr.value + die.cu.cu_offset)


def parse_type_die(die,var_data,dwarfinfo):
    if 'DW_AT_type' not in die.attributes:  
        var_data['type'].append('void')
        return
    
    type_die = get_DIE_by_reference(die, "DW_AT_type", dwarfinfo)
    tag = type_die.tag
    
    # Base types (e.g., int, char)
    if tag == 'DW_TAG_base_type':
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        var_data['size'] = type_die.attributes['DW_AT_byte_size'].value
        return
    
    #follow typedef
    elif tag == 'DW_TAG_typedef':
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        parse_type_die(type_die, var_data, dwarfinfo)
        var_data['is_typedef'] = True
        return
    
    # Array types
    elif tag == 'DW_TAG_array_type':
        prev_type = var_data['type'][:]
        var_data['type'] = []
        parse_type_die(type_die, var_data, dwarfinfo)
        array_size = get_array_dims(type_die, dwarfinfo)
        
        
        var_data['array_length'] = array_size[0] if (array_size!=[] and array_size[0]) else 1
        var_data['element_type'] = var_data['type'][:]
        var_data['element_size'] = var_data['size']
        
        for i in range(len(var_data['type'])):
            var_data['type'][i] += f'[{array_size[0]}]' if (len(array_size) and array_size[0]) else '[]'
        
        var_data['type'] = prev_type + var_data['type']
        if len(array_size) and array_size[0]:
            var_data['size'] *= array_size[0] 
        
        var_data['is_array'] = True
        return
    
    # Pointer types
    elif tag == 'DW_TAG_pointer_type':
        prev_type = var_data['type'][:]
        var_data['type'] = []
        
        parse_type_die(type_die,var_data, dwarfinfo)
        
        if var_data['type'] == []:
            var_data['type'].append('void')
        
        for i in range(len(var_data['type'])):
            var_data['type'][i] +=  '*'

        var_data['type'] = prev_type + var_data['type']
        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 8
        var_data['is_pointer'] = True
        var_data['is_array'] = False
        var_data['is_struct'] = False
        return
    
    #constant types
    elif tag == 'DW_TAG_const_type' or tag == 'DW_TAG_volatile_type':
        parse_type_die(type_die, var_data, dwarfinfo)
        return

    # Struct types
    elif tag =='DW_TAG_structure_type':
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        
        if var_data['type'] == []:
            var_data['type'].append('struct')
        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 8
        var_data['is_struct'] = True
        return
    
    #union types
    elif tag in ('DW_TAG_union_type', 'DW_TAG_class_type'):
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        
        if var_data['type'] == []:
            var_data['type'].append('struct')
        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 8        
        var_data['is_union'] = True   
        return

    # Enum types
    elif tag == 'DW_TAG_enumeration_type':
        if 'DW_AT_name' in type_die.attributes:
            var_data['type'].append(type_die.attributes['DW_AT_name'].value.decode('utf-8', 'replace'))
        var_data['type'].append('int')
        var_data['size'] = type_die.attributes.get('DW_AT_byte_size').value if 'DW_AT_byte_size' in type_die.attributes else 4      
        var_data['is_enum'] = True
        return
    
    #Function Types
    elif tag == 'DW_TAG_subroutine_type':
        var_data['type'].append('FUNCTION')
        return

    else:
        return


def parse_variable_die(child_die, dwarfinfo):
    var_data = {}
    var_data['name'] = ''
    var_data['RBP offset'] = []
    var_data['type'] = [] #array to take care of typedef chaining
    var_data['size'] = 0
    var_data['is_pointer'] = False
    var_data['is_typedef'] = False
    var_data['is_array'] = False
    var_data['is_struct'] = False
    var_data['is_union'] = False
    var_data['is_enum'] = False

    var_data['RBP offset'] = get_location(child_die,dwarfinfo)
    var_data['RBP offset'] = list(set(var_data['RBP offset']))  # Remove duplicates
    
    #Not a Stack Variable
    if var_data['RBP offset'] == []:
        return None

    if 'DW_AT_abstract_origin' in child_die.attributes:
        child_die = get_DIE_by_reference(child_die, "DW_AT_abstract_origin", dwarfinfo)
    
    var_name = child_die.attributes.get('DW_AT_name').value.decode('utf-8','replace') if 'DW_AT_name' in child_die.attributes else ''
    var_data['name'] = var_name

    parse_type_die(child_die, var_data, dwarfinfo)
    var_data['type'] = get_normalized_types(var_data['type'])

    var_data['type'] = list(set(var_data['type']))  # Remove duplicates

    if var_data['is_array']:
        var_data['element_type'] = get_normalized_types(var_data['element_type'])
    
    # if var_data['is_struct']:
    #     var_data['elements'] = []
    #     parse_struct(child_die, var_data, dwarfinfo)
    

    return var_data


def parse_lexical_block(die, dwarfinfo):
    variables = []
    
    for child in die.iter_children():
        if child.tag == 'DW_TAG_lexical_block':
            variables.extend(parse_lexical_block(child, dwarfinfo))
        
        elif child.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
            var_data = parse_variable_die(child, dwarfinfo)
            
            if var_data:
                variables.append(var_data)
    
    return variables
            


def parse_function_die(die,dwarfinfo):
    func_data = {}

    if 'DW_AT_name' not in die.attributes:
        return None, None
    
    func_name = die.attributes.get('DW_AT_name').value.decode('utf-8', 'replace')
    # print(f"Processing function: {func_name}")
    address = 0
    
    # if 'DW_AT_low_pc' in die.attributes:
    #     address = die.attributes.get('DW_AT_low_pc').value
    # else:
    #     address = die.attributes.get('DW_AT_entry_pc').value if 'DW_AT_entry_pc' in die.attributes else 0

    # if address == 0:
    #     return None, None

    # func_data['address'] = hex(address)
    func_data['variables'] = []
    
    for child in die.iter_children():
        
        if child.tag in ('DW_TAG_lexical_block', 'DW_TAG_inlined_subroutine'):
            func_data['variables'].extend(parse_lexical_block(child, dwarfinfo))
        
        elif child.tag in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
            var_data = parse_variable_die(child, dwarfinfo)
            if var_data:
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
            if func_name:
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
