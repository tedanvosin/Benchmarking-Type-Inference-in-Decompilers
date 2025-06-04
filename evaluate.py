#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from collections import OrderedDict

DECOMPILERS = ['angr','binja','ghidra','ida','retypd']
DECOMP_JSONS = []

def evaluate_structs(decomp_json, gt_json):
    global_variables_identified = 0
    global_corret_cnt = 0
    global_ghost_variables = 0
    
    for func in gt_json:
        has_arr_struct = False

        for var in gt_json[func]['variables']:
            if not var['is_pointer'] and var['is_struct']:
                has_arr_struct = True
                break

        if not has_arr_struct:
            continue
        
        variables_identified = 0
        corret_cnt = 0
        ghost_variables = 0
        
        if func not in decomp_json:
            print(f'Function {func} not found in decomp')
            continue
        
        gt_variables = gt_json[func]['variables']
        decomp_variables = decomp_json[func]['variables']
        
        
        decomp_variables_types = {}
        for decomp_var in decomp_variables:
            decomp_variables_types[decomp_var['RBP offset']] = decomp_var['type'].replace('unsigned ','').replace(' ','')
        
        
        gt_variables_types = {}
        for gt_var in gt_variables:
            gt_variables_types[gt_var['RBP offset']] = []
            
            ##Check if varable is a Struct
            if not gt_var['is_pointer'] and gt_var['is_struct']:
                
                #If variable is a struct and matched, dont break struct type
                if gt_var['RBP offset'] in decomp_variables_types and decomp_variables_types[gt_var['RBP offset']] in gt_var['type']:
                    for var_type in gt_var['type']:
                        gt_variables_types[gt_var['RBP offset']].append(var_type.replace('unsigned ','').replace(' ',''))
                
                #break struct type if not matched
                else:
                    for var in gt_var['elements']:
                        
                        if var['RBP offset'] not in gt_variables_types:
                            gt_variables_types[var['RBP offset']] = []
                        
                        for var_type in var['type']:
                            gt_variables_types[var['RBP offset']].append(var_type.replace('unsigned ','').replace(' ',''))

            #If not struct continue as normal
            else:
                for var_type in gt_var['type']:
                    gt_variables_types[gt_var['RBP offset']].append(var_type.replace('unsigned ','').replace(' ',''))
        
        for offset in decomp_variables_types:
            if offset in gt_variables_types:
                variables_identified += 1
                if decomp_variables_types[offset] in gt_variables_types[offset]:
                    corret_cnt += 1
            else:
                ghost_variables += 1
          
        global_variables_identified += variables_identified
        global_corret_cnt += corret_cnt
        global_ghost_variables += ghost_variables
        print(f"{func:<20}{'Yes'if (has_arr_struct) else 'No' :<19}{f'{len(decomp_variables_types)}/{len(gt_variables_types)}':<25}{variables_identified:<20}{corret_cnt:<15}{ghost_variables:<15}")
    
    return global_variables_identified, global_corret_cnt, global_ghost_variables

def primitive_evaluation(decomp_json, gt_json):

    for func in gt_json:
        
        gt_var_types = {}
        for var in gt_json[func]['variables']:
            if var['is_pointer'] or var['is_struct'] or var['is_array'] or var['is_union']:
                continue
            for var_type in var['type']:
                gt_var_types[var['RBP offset']] = var_type.replace('unsigned ','').replace(' ','')
    

def basic_evaluation(decomp_json, gt_json, arr_struct=False):
    global_variables_identified = 0
    global_corret_cnt = 0
    global_ghost_variables = 0
    
    for func in gt_json:
        has_arr_struct = False

        for var in gt_json[func]['variables']:
            if not var['is_pointer'] and var['is_struct']:
                has_arr_struct = True
                break
            elif var['is_array']:
                has_arr_struct = True
                break
        
        if (has_arr_struct and not arr_struct) or (not has_arr_struct and arr_struct):
            continue
        
        variables_identified = 0
        corret_cnt = 0
        ghost_variables = 0
        
        if func not in decomp_json:
            print(f'Function {func} not found in decomp')
            continue
        
        gt_variables = gt_json[func]['variables']
        decomp_variables = decomp_json[func]['variables']
        
        gt_variables_info = {}

        for gt_var in gt_variables:
            gt_variables_info[gt_var['RBP offset']] = []
            for var_type in gt_var['type']:
                gt_variables_info[gt_var['RBP offset']].append(var_type.replace('unsigned ','').replace(' ',''))
        
        decomp_variables_info = {}

        for decomp_var in decomp_variables:
            decomp_variables_info[decomp_var['RBP offset']] = decomp_var['type'].replace('unsigned ','').replace(' ','')

        for offset in decomp_variables_info:
            if offset in gt_variables_info:
                variables_identified += 1
                if decomp_variables_info[offset] in gt_variables_info[offset]:
                    corret_cnt += 1
            else:
                ghost_variables += 1
          
        global_variables_identified += variables_identified
        global_corret_cnt += corret_cnt
        global_ghost_variables += ghost_variables
        print(f"{func:<20}{'Yes'if (has_arr_struct) else 'No' :<19}{f'{len(decomp_variables_info)}/{len(gt_variables_info)}':<25}{variables_identified:<20}{corret_cnt:<15}{ghost_variables:<15}")
    
    return global_variables_identified, global_corret_cnt, global_ghost_variables



def evaluate(decomp_json, gt_json):
    total_variables_in_gt = 0
    total_variables_in_decomp = 0
    
    for func in gt_json:
        total_variables_in_gt += len(gt_json[func]['variables'])
        if func in decomp_json:
            total_variables_in_decomp += len(decomp_json[func]['variables'])
    
    print(f'Total variables in ground truth: {total_variables_in_gt}')
    print(f'Total variables in Decompilation: {total_variables_in_decomp}\n')
    

    print(f"{'Function Name':<20}{'Has array/struct':<19}{'Variables Identified':<25}{'Correct Offset':<20}{'Correct Type':<15}{'Ghosts':<15}")

    global_variables_identified = 0
    global_corret_cnt = 0
    global_ghost_variables = 0
    
    basic_evaluation(decomp_json, gt_json)
    print()
    basic_evaluation(decomp_json, gt_json, arr_struct=True)
    print()
    print("Now Breaking Structs into Elements")
    evaluate_structs(decomp_json, gt_json)
    
    # print(f'\nTotal variables identified: {global_variables_identified}, Correct Variables: {global_corret_cnt}, Ghost Variables: {global_ghost_variables}')
        
    return

def main():
    
    base_dir = f'binaries/{sys.argv[1]}' if len(sys.argv) > 1 else 'binaries/O0'
    base_dir = Path(base_dir)
    
    file_list = open(base_dir/'file_list.txt','r').readlines()
    file_list = [x.strip() for x in file_list]
        
    for file in file_list:
        file_path = base_dir / file
        file_name = file_path.stem
        
        ground_truth = base_dir / 'types' /'ground_truth'/f'{file_name}.json'
        
        if ground_truth.exists():
            print(f'\n----------------Processing {file_name}----------------\n')

            gt_json = json.loads(ground_truth.read_text())
            
            for decompiler in DECOMPILERS:
                
                decomp_json_path = base_dir / 'types' /f'{decompiler}_types'/f'{file_name}.json'
                
                if decomp_json_path.exists():
                    print(f'\n----------------Processing {decompiler}----------------\n')
                    
                    decomp_json = json.loads(decomp_json_path.read_text())                    
                    evaluate(decomp_json, gt_json)


if __name__ == "__main__":
    main()