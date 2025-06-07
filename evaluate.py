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

def var_level_evaluate(var_type_str):
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT Cnt", "TP", "FP", "TN", "FN"))
    print(f"{'':-<60}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for i in range(len(GROUND_TRUTHS)):
            ground_truth_json = json.load(open(GROUND_TRUTHS[i]))
            decomp_json = json.load(open(DECOMPS[decompiler][i]))
    
            gt_funcs = {}
            decomp_funcs = {}
            
            for func in ground_truth_json:
                
                gt_funcs[func] = {}
                
                if func in decomp_json:
                    decomp_funcs[func] = {}
                    for var in decomp_json[func]['variables']:
                        if var['RBP offset'] not in decomp_funcs[func]:
                            decomp_funcs[func][var['RBP offset']] = []
                        decomp_funcs[func][var['RBP offset']].append(var['type'].strip().replace(' ', ''))
                
                for var in ground_truth_json[func]['variables']:
                    gt_funcs[func][var['RBP offset']] = []
                    for type in var['type']:
                        gt_funcs[func][var['RBP offset']].append(type.replace(' ',''))  


            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,_type in gt_funcs[func].items():
                        if var_type_str in _type:
                            fn += 1
                    continue
                
                for offset,_type in gt_funcs[func].items():
                    if var_type_str not in _type:
                        continue
                    if offset in decomp_funcs[func]:
                        if var_type_str in decomp_funcs[func][offset]:
                            tp += 1
                        else:
                            fp += 1
                    else:
                        fn += 1
                
                for offset in decomp_funcs[func]:
                    if offset not in gt_funcs[func]:
                        if var_type_str in set(decomp_funcs[func][offset]):
                            tn += 1

        
        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, tn, fn))
    print("\n")

def func_level_evaluate(allow_structs=True, allow_arrays=True, primitives=True, break_structs=False,depth=1):
    
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT Cnt", "TP", "FP", "TN", "FN"))
    print(f"{'':-<60}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        tn = 0
        fp = 0
        fn = 0
        var_cnt = 0

        for i in range(len(GROUND_TRUTHS)):
            ground_truth_json = json.load(open(GROUND_TRUTHS[i]))
            decomp_json = json.load(open(DECOMPS[decompiler][i]))
    
            gt_funcs = {}
            decomp_funcs = {}
            
            for func in ground_truth_json:
                if not allow_arrays and has_array(ground_truth_json[func]):
                    continue
                if not allow_structs and has_struct(ground_truth_json[func]):
                    continue
                if not primitives and not (has_array(ground_truth_json[func]) or has_struct(ground_truth_json[func])):
                    continue
                
                gt_funcs[func] = {}
                
                if func in decomp_json:
                    decomp_funcs[func] = {}
                    for var in decomp_json[func]['variables']:
                        if var['RBP offset'] not in decomp_funcs[func]:
                            decomp_funcs[func][var['RBP offset']] = []
                        decomp_funcs[func][var['RBP offset']].append(var['type'].strip().replace(' ', ''))
                
                for var in ground_truth_json[func]['variables']:
                    if var['is_struct'] and break_structs:
                        
                        if (func in decomp_funcs) and (var['RBP offset'] in decomp_funcs[func]) and (set(var['type']).intersection(set(decomp_funcs[func][var['RBP offset']]))):
                            #Struct Identified
                            gt_funcs[func][var['RBP offset']] = []
                            for type in var['type']:
                                gt_funcs[func][var['RBP offset']].append(type.replace(' ',''))    
                        
                        else:
                            #Struct Not Identified
                            #Breakdown Struct
                            break_struct(var, gt_funcs[func], depth=depth)
                            
                    else:
                        gt_funcs[func][var['RBP offset']] = []
                        for type in var['type']:
                            gt_funcs[func][var['RBP offset']].append(type.replace(' ',''))  

            for func in gt_funcs:
                if func not in decomp_funcs:
                    fn += len(gt_funcs[func])
                    continue
                
                for offset,_type in gt_funcs[func].items():
                    var_cnt += 1
                    if offset in decomp_funcs[func]:
                        if set(gt_funcs[func][offset]).intersection(set(decomp_funcs[func][offset])):
                            tp += 1
                        else:
                            fp += 1
                    else:
                        fn += 1

                for offset in decomp_funcs[func]:
                    if offset not in gt_funcs[func]:
                        tn += 1
        
        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, tn, fn))
    print("\n")


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

    print("==========================================================")
    print("Function Level Evaluations\n")
    print("Keys:")
    print("TP (True Positive):        Identified Offset in ground truth and same type")
    print("FP (False Positive):       Identified Offset in ground truth but wrong type")
    print("TN (True Negative/Ghosts): Identified Offset not in ground truth")
    print("FN (False Negative):       Offset in ground truth not identified\n")
    
    print(f"Evaluating {len(GROUND_TRUTHS)} files with {sum(len(json.load(open(p))) for p in GROUND_TRUTHS)} functions\n")

    print("[*] Basic Evaluation")
    print("[*] Includes all functions, and no breakdown of sturctures\n")
    func_level_evaluate(allow_arrays=True, allow_structs=True)

    print("[*] Primitives and Pointers Evaluation") 
    print("[*] Includes functions with only primitive types and pointers\n")
    func_level_evaluate(allow_arrays=False, allow_structs=False)

    print("[*] Struct and Array Evaluation")
    print("[*] Excludes functions without structs and arrays\n")
    func_level_evaluate(allow_arrays=True, allow_structs=True, primitives=False)

    print("[*] Evaluation with Struct Breakdown by 1 level")
    print("[*] Excludes functions without structs and arrays\n")
    func_level_evaluate(allow_arrays=True, allow_structs=True, primitives=False, break_structs=True,depth=1)

    print("==========================================================")
    print("Variable Level Evaluations\n")
    
    print("Keys:")
    print("TP (True Positive):        Identified Offset in ground truth and same type")
    print("FP (False Positive):       Identified Offset in ground truth but wrong type")
    print("TN (True Negative/Ghosts): Identified Offset not in ground truth")
    print("FN (False Negative):       Offset in ground truth not identified\n")

    print("[*] Evaluating char\n")
    var_level_evaluate('char')

    print("[*] Evaluating int\n")
    var_level_evaluate('int')

    print("[*] Evaluating long long\n")
    var_level_evaluate('longlong')


if __name__ == "__main__":
    main()