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

def get_aray_length(var):
    if var['is_array']:
        type_str = var['type']
        len = type_str[type_str.index('[')+1:type_str.index(']')]
        len = int(len)
        return len
    else:
        return 0
    
def get_base_type(var):
    base_types = []
    for type in var:
        if '[' in type:
            base_types.append(type[:type.index('[')])
        else:
            base_types.append(type)
    return base_types

def eval_array():
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT off", "TP", "FP","FP_1","FN"))
    print(f"{'':-<60}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        fp = 0
        fp_1 = 0  #correct base type, wrong length
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
                            decomp_funcs[func][var['RBP offset']] = {}
                            decomp_funcs[func][var['RBP offset']]['type'] = []
                        
                        decomp_funcs[func][var['RBP offset']]['type'].append(var['type'].strip().replace(' ', ''))

                for var in ground_truth_json[func]['variables']:
                    if not var['is_array']:
                        continue 
                    else:
                        gt_funcs[func][var['RBP offset']] = {}
                        gt_funcs[func][var['RBP offset']]['type'] = []
                        gt_funcs[func][var['RBP offset']]['size'] = var['size']
                        gt_funcs[func][var['RBP offset']]['base'] = var['element_type']
                        gt_funcs[func][var['RBP offset']]['length'] = var['array_length']
                        for type in var['type']:
                            gt_funcs[func][var['RBP offset']]['type'].append(type.replace(' ',''))
              
            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,_type in gt_funcs[func].items():
                        fn += 1
                else:
                    for offset,_type in gt_funcs[func].items():
                        if offset in decomp_funcs[func]:
                            if set(gt_funcs[func][offset]['type']).intersection(set(decomp_funcs[func][offset]['type'])):
                                tp += 1
                            else:
                                if set(gt_funcs[func][offset]['base']).intersection(get_base_type(decomp_funcs[func][offset]['type'])):
                                    #correctbase_wrong_length
                                    fp += 1
                                else:
                                    #wrong base type
                                    fp_1 +=1 
                        else:
                            fn += 1

        else:
            print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp+fp_1}/{tp+fp+fp_1+fn}', tp, fp, fp_1, fn))
    print("\n")
    return

def eval_structs(l1_break=False):
    if l1_break:
        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<15}".format("Decompiler","Decomp/GT Cnt", "TP", "FP","FN","Structs Broken"))
    else:
        print("{:<13}{:<15}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT Cnt", "TP", "FP","FN"))
    print(f"{'':-<52}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        fp = 0
        fn = 0
        br=0
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
                    if not var['is_struct']:
                        continue 
                    
                    if l1_break:
                        if (func in decomp_funcs) and (var['RBP offset'] in decomp_funcs[func]) and (set(var['type']).intersection(set(decomp_funcs[func][var['RBP offset']]))):
                            #Struct Identified
                            continue
                        
                        else:
                            #Struct Not Identified
                            #Breakdown Struct
                            br+=1
                            break_struct(var, gt_funcs[func], depth=1)
                            
                    else:
                        gt_funcs[func][var['RBP offset']] = []
                        for type in var['type']:
                            gt_funcs[func][var['RBP offset']].append(type.replace(' ',''))
              
            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,_type in gt_funcs[func].items():
                        fn += 1
                else:
                    for offset,_type in gt_funcs[func].items():
                        if offset in decomp_funcs[func]:
                            if set(gt_funcs[func][offset]).intersection(set(decomp_funcs[func][offset])):
                                tp += 1
                            else:
                                # print(f"({decompiler})Wrong type GT: {gt_funcs[func][offset]} Decomp: {decomp_funcs[func][offset]}")
                                fp += 1
                        else:
                            fn += 1

        if l1_break:
            print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp}/{tp+fp+fn}', tp, fp, fn, br))
        else:
            print("{:<13}{:<15}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp}/{tp+fp+fn}', tp, fp, fn))
    print("\n")
    return

def eval_pointers():
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT Cnt", "TP", "FP","FP_1", "TN", "FN"))
    print(f"{'':-<68}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        tn = 0
        fp = 0
        fp_1 = 0
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
                            decomp_funcs[func][var['RBP offset']] = {}
                            decomp_funcs[func][var['RBP offset']]['type'] = []
                            decomp_funcs[func][var['RBP offset']]['is_pointer'] = False
                        
                        if '*' in var['type']:
                            decomp_funcs[func][var['RBP offset']]['is_pointer'] = True
                        decomp_funcs[func][var['RBP offset']]['type'].append(var['type'].strip().replace(' ', ''))

                for var in ground_truth_json[func]['variables']:
                    if var['RBP offset'] not in gt_funcs[func]:
                        gt_funcs[func][var['RBP offset']] = {}
                        gt_funcs[func][var['RBP offset']]['type'] = []
                        gt_funcs[func][var['RBP offset']]['is_pointer'] = False
                    
                    if not gt_funcs[func][var['RBP offset']]['is_pointer']:
                        gt_funcs[func][var['RBP offset']]['is_pointer'] = var['is_pointer']
                    
                    for type in var['type']:
                        gt_funcs[func][var['RBP offset']]['type'].append(type.replace(' ',''))  


            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,var_json in gt_funcs[func].items():
                        if var_json['is_pointer']:
                            fn += 1
                else:
                    for offset,var_json in gt_funcs[func].items():
                        if not var_json['is_pointer']:
                            continue
                        if offset in decomp_funcs[func]:
                            if decomp_funcs[func][offset]['is_pointer']:
                                if set(gt_funcs[func][offset]['type']).intersection(set(decomp_funcs[func][offset]['type'])):
                                    tp += 1
                                else:
                                    fp += 1
                            else:
                                fp_1 += 1
                        else:
                            fn += 1
                
                    # for offset in decomp_funcs[func]:
                    #     if offset not in gt_funcs[func]:
                    #         if decomp_funcs[func][offset]['is_pointer']:
                    #             tn += 1

        
        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp+tn+fp_1}/{tp+fp+fp_1+fn}', tp, fp, fp_1, tn, fn))
    print("\n")
    return

def var_level_evaluate(var_type_str,exp_size):
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}".format("Decompiler","Decomp/GT Off", "TP", "FP", "TN", "FN", "C_SZ", "W_SZ"))
    print(f"{'':-<76}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        tn = 0
        fp = 0
        fn = 0
        w_sz = 0
        c_sz = 0
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
                            decomp_funcs[func][var['RBP offset']] = {}
                            decomp_funcs[func][var['RBP offset']]['type'] = []
                            decomp_funcs[func][var['RBP offset']]['size'] = []
                        
                        decomp_funcs[func][var['RBP offset']]['type'].append(var['type'].strip().replace(' ', ''))
                        decomp_funcs[func][var['RBP offset']]['size'].append(var['size'])

                for var in ground_truth_json[func]['variables']:
                    if var['RBP offset'] not in gt_funcs[func]:
                        gt_funcs[func][var['RBP offset']] = {}
                        gt_funcs[func][var['RBP offset']]['type'] = []
                        gt_funcs[func][var['RBP offset']]['size'] = []
                    
                    gt_funcs[func][var['RBP offset']]['size'].append(var['size'])
                    for type in var['type']:
                        gt_funcs[func][var['RBP offset']]['type'].append(type.replace(' ',''))  


            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,var_json in gt_funcs[func].items():
                        _type = var_json['type']
                        if var_type_str in _type:
                            fn += 1
                    continue
                
                for offset,var_json in gt_funcs[func].items():
                    _type = var_json['type']
                    if var_type_str not in _type:
                        continue
                    if offset in decomp_funcs[func]:
                        
                        if var_type_str in decomp_funcs[func][offset]['type']:
                            tp += 1
                            c_sz+=1
                        
                        else:
                            if (exp_size in decomp_funcs[func][offset]['size']) and (exp_size in gt_funcs[func][offset]['size']): 
                                # Size matches, but type does not
                                c_sz += 1
                            else:
                                # Size does not match
                                # print(f"Wrong type GT: {gt_funcs[func][offset]} Decomp: {decomp_funcs[func][offset]}")
                                w_sz += 1
                            fp += 1
                    else:
                        fn += 1
                
                # for offset in decomp_funcs[func]:
                #     if offset not in gt_funcs[func]:
                #         if var_type_str in set(decomp_funcs[func][offset]['type']):
                #             tn += 1

        
        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<8}{:<8}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, tn, fn,c_sz, w_sz))
    print("\n")

def func_level_evaluate(allow_structs=True, allow_arrays=True, primitives=True, break_structs=False,depth=1):
    
    print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<10}".format("Decompiler","Decomp/GT Cnt", "TP", "FP", "TN", "FN", "Coverage"))
    print(f"{'':-<70}")
    
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

        print("{:<13}{:<15}{:<8}{:<8}{:<8}{:<8}{:<10}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, tn, fn, f'{(tp+fp)/(tp+fp+fn) * 100:.2f}'))
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
    print("TP   (True Positive):        Identified Offset in ground truth and same type")
    print("FP   (False Positive):       Identified Offset in ground truth but wrong type")
    print("TN   (True Negative/Ghosts): Identified Offset not in ground truth")
    print("FN   (False Negative):       Offset in ground truth not identified")
    print("C_SZ (Correct size):         Identified Offset in ground truth and correct size")
    print("W_SZ (Wrong size):           Identified Offset in ground truth but wrong size\n")

    print("[*] Evaluating bool\n")
    var_level_evaluate('bool',1)
    
    print("[*] Evaluating char\n")
    var_level_evaluate('char',1)

    print("[*] Evaluating int\n")
    var_level_evaluate('int',4)

    print("[*] Evaluating long long\n")
    var_level_evaluate('longlong',8)
    
    print("Keys:")
    print("TP   (True Positive):        Identified Offset in ground truth and same type of pointer")
    print("FP   (False Positive):       Identified Offset in ground truth but wrong type of pointer")
    print("FP_1 (False Positive):       Identified Offset in ground truth but not a pointer")
    print("TN   (True Negative/Ghosts): Identified Offset not in ground truth")
    print("FN   (False Negative):       Offset in ground truth not identified\n")


    print("[*] Evaluating Pointers\n")
    eval_pointers()

    print("Keys:")
    print("TP   (True Positive):        Identified Offset in ground truth and same type of struct")
    print("FP   (False Positive):       Identified Offset in ground truth but not a struct")
    print("FN   (False Negative):       Offset in ground truth not identified\n")


    print("[*] Evaluating Structs\n")
    eval_structs()

    print("Keys:")
    print("TP   (True Positive):        Correct array base and length")
    print("FP   (False Positive):       Correcty base, wrong length")
    print("FP_1 (False Positive):       Correct offset wrong base")
    print("FN   (False Negative):       Offset in ground truth not identified\n")


    print("[*] Evaluating Arrays\n")
    eval_array()

if __name__ == "__main__":
    main()