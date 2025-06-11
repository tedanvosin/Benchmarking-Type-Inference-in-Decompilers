#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from pprint import pprint
from collections import OrderedDict

DECOMPILERS = ['angr','binja','ghidra','ida','retypd']
DECOMPS = {'angr':[],'binja':[],'ghidra':[],'ida':[],'retypd':[]}
GROUND_TRUTHS = []

def has_array(func):
    for var in func['variables']:
        if var['is_array']:
            return True
    return False

def has_struct(func):
    for var in func['variables']:
        if var['is_struct']:
            return True
    return False

def has_pointer(func):
    for var in func['variables']:
        if var['is_pointer']:
            return True
    return False

def break_struct(var,gt_funcs,depth=1):
    if depth == 0:
        gt_funcs[var['RBP offset']] = []
        for type in var['type']:
            gt_funcs[var['RBP offset']].append(type.replace(' ',''))
        return
    
    for mem in var['elements']:
        if mem['is_struct']:
            break_struct(mem, gt_funcs,depth-1)
            return
        
        gt_funcs[mem['RBP offset']] = []
        for type in mem['type']:
            gt_funcs[mem['RBP offset']].append(type.replace(' ',''))

def type_check():
    types = set()
    gt_files = GROUND_TRUTHS
    for gt_file in  gt_files:
        gt_json = json.loads(gt_file.read_text())
        for func_name, func in gt_json.items():
            variables = func['variables']
            for vr in variables:
                if 'type' not in vr:
                    continue
                for type in vr['type']:
                    _type = type.replace(' ','')
                    types.add(_type)
    
    print(f"Types found in Ground truth: {len(types)}")
    print("Types:")
    for type in sorted(types):
        print(type)
    print("\n\n")

    for decompiler in DECOMPILERS:
        types = set()
        decomp_files = DECOMPS[decompiler]
        for decomp_file in  decomp_files:
            decomp_json = json.loads(decomp_file.read_text())
            for func_name, func in decomp_json.items():
                variables = func['variables']
                for vr in variables:
                    if 'type' not in vr:
                        continue
                    _type = vr['type'].replace(' ','')
                    types.add(_type)
        
        print(f"Types found in {decompiler}: {len(types)}")
        print("Types:")
        for type in sorted(types):
            print(type)
        print("\n\n")


def main():
    base_dir = f'binaries/{sys.argv[1]}' if len(sys.argv) > 1 else 'binaries/O0'
    base_dir = Path(base_dir)
    
    file_list = open(base_dir/'file_list.txt','r').readlines()
    file_list = [file.strip() for file in file_list]
    
    for file in file_list:
        file_path = base_dir / file
        file_name = file_path.stem
        
        ground_truth = base_dir / 'types' /'ground_truth'/f'{file_name}.json'
        if not ground_truth.exists():
            continue
        
        decomp_files = {}
        for decomp in DECOMPILERS:
            decomp_files[decomp] = base_dir / 'types' / f'{decomp}_types' / f'{file_name}.json'
        
        if not all(decomp_file.exists() for decompiler, decomp_file in decomp_files.items()):
            continue        
        
        GROUND_TRUTHS.append(ground_truth)
        for decomp in DECOMPILERS:
            DECOMPS[decomp].append(decomp_files[decomp])

    type_check()

if __name__ == "__main__":
    main()