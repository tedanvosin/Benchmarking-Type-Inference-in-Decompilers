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

def has_complex(func):
    for var in func['variables']:
        if var['is_struct'] or var['is_array']:
            return True
    return False

def is_array(type):
    for _type in type:
        if '[' in _type and ']' in _type:
            return True
    return False

def get_base_type(var):
    base_types = []
    for type in var:
        if '[' in type:
            base_types.append(type[:type.index('[')])
        else:
            base_types.append(type)
    return base_types

def eval_array():
    print("{:^13}|{:^23}|{:^9}|{:^14}|{:^7}|{:^19}|{:^21}|{:^31}".format("Decompilers","Variables Identified/","Correct","Correct Base","Wrong" ,"Variable in GT"   ,"% of Arrays"         , "% of Arrays identified with"))
    print("{:^13}|{:^23}|{:^9}|{:^14}|{:^7}|{:^19}|{:^21}|{:^31}".format(""           ,"Variables in GT"      ,"Type"   ,"Wrong Length","Type"  ,"but not in Decomp","Correctly Identified", "correct base but wrong length"))
    print(f"{'':-<144}")
    
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
                                if is_array(decomp_funcs[func][offset]['type']) and set(gt_funcs[func][offset]['base']).intersection(get_base_type(decomp_funcs[func][offset]['type'])):
                                    #correctbase_wrong_length
                                    fp += 1
                                else:
                                    #wrong base type
                                    fp_1 +=1 
                        else:
                            fn += 1
        
        
        pci = tp/(tp+fp+fp_1+fn) *100
        cbwl = fp/(tp+fp+fp_1+fn) *100
        
        print("{:^13}|{:>23}|{:>9}|{:>14}|{:>7}|{:>19}|{:>21}|{:>31}".format(decompiler,f'{tp+fp+fp_1}/{tp+fp+fp_1+fn}', tp, fp, fp_1, fn,f'{pci:.2f}',f'{cbwl:.2f}'))
        # print(f"Usual failed lengths:{wrong_lens}")
    print("\n")
    return

def eval_structs():
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^19}|{:^21}".format("Decompilers","Variables Identified/","Correct","Wrong" ,"Variable in GT"   ,"Struct Identification"))
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^19}|{:^21}".format(""           ,"Variables in GT"      ,"Type"   ,"Type"  ,"but not in Decomp","Accuracy (%)"))
    print(f"{'':-<97}")
    
    st_identified = {}
    st_misidentified = {}
    for decompiler in DECOMPILERS:
        tp = 0
        fp = 0
        fn = 0
        br=0
        st_identified[decompiler] = set()
        st_misidentified[decompiler] = {}
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
                    
                    ##overlapping struct
                    if var['RBP offset'] not in gt_funcs[func]:
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
                                st_identified[decompiler].add(gt_funcs[func][offset][-1])
                            else:
                                fp += 1
                                if gt_funcs[func][offset][-1] not in st_misidentified[decompiler]:
                                    st_misidentified[decompiler][gt_funcs[func][offset][-1]] = set()
                                st_misidentified[decompiler][gt_funcs[func][offset][-1]].add(decomp_funcs[func][offset][-1])
                        else:
                            fn += 1

        sia = tp/(tp+fp+fn) * 100
        print("{:^13}|{:>23}|{:>9}|{:>7}|{:>19}|{:>21}".format(decompiler,f'{tp+fp}/{tp+fp+fn}', tp, fp, fn,f'{sia:.2f}'))
    
    for decompiler in DECOMPILERS:
        print(decompiler)
        print(f"Structs Identified: {list(st_identified[decompiler])}")
        
        # for gt_st,dc_st in st_misidentified[decompiler].items():
        #     print(f"Struct {gt_st} misidentified as: {dc_st}")
    
    print("\n")
    return

def eval_pointers():
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^9}|{:^19}|{:^9}|{:^9}|{:^24}|{:^18}|{:^14}".format("Decompilers","Variables Identified/","Correct","Wrong" ,"Not a"  ,"Variable in GT"   ,"Correct","Wrong","Pointer Identification","Target Resolution","Size Inference"))
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^9}|{:^19}|{:^9}|{:^9}|{:^24}|{:^18}|{:^14}".format(""           ,"Variables in GT"      ,"Target" ,"Target","Pointer","but not in Decomp","Size"   ,"Size" ,"Accuracy(%)"           ,"Accuracy(%)"      ,"Accuracy(%)"))
    print(f"{'':-<164}")
    
    for decompiler in DECOMPILERS:
        tp = 0
        tn = 0
        fp = 0
        fp_1 = 0
        fn = 0
        c_sz=0
        w_sz=0
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
                            decomp_funcs[func][var['RBP offset']]['size'] = []
                        
                        if '*' in var['type']:
                            decomp_funcs[func][var['RBP offset']]['is_pointer'] = True
                        decomp_funcs[func][var['RBP offset']]['type'].append(var['type'].strip().replace(' ', ''))
                        decomp_funcs[func][var['RBP offset']]['size'].append(var['size'])
                
                for var in ground_truth_json[func]['variables']:
                    if not var['is_pointer']:
                        continue
                    if var['RBP offset'] not in gt_funcs[func]:
                        gt_funcs[func][var['RBP offset']] = {}
                        gt_funcs[func][var['RBP offset']]['type'] = []
                    
                    for type in var['type']:
                        gt_funcs[func][var['RBP offset']]['type'].append(type.replace(' ',''))  


            for func in gt_funcs:
                if func not in decomp_funcs:
                    for offset,var_json in gt_funcs[func].items():
                        fn += 1
                else:
                    for offset,var_json in gt_funcs[func].items():
                        if offset in decomp_funcs[func]:
                            if decomp_funcs[func][offset]['is_pointer']:
                                if set(gt_funcs[func][offset]['type']).intersection(set(decomp_funcs[func][offset]['type'])):
                                    tp += 1
                                    
                                else:
                                    fp += 1
                                
                            else:
                                fp_1 += 1
                            
                            if 8 in decomp_funcs[func][offset]['size']:
                                c_sz+=1
                            else:
                                w_sz+=1
                        
                        else:
                            fn += 1
        
        pia = (tp+fp)/(tp+fp+fp_1+fn) *100
        tra = (tp)/(tp+fp+fp_1+fn) * 100
        sia = c_sz/(c_sz+w_sz) * 100
        print("{:^13}|{:>23}|{:>9}|{:>7}|{:>9}|{:>19}|{:>9}|{:>9}|{:>24}|{:>18}|{:>14}".format(decompiler,f'{tp+fp+tn+fp_1}/{tp+fp+fp_1+fn}', tp, fp, fp_1, fn, c_sz,w_sz,f'{pia:.2f}',f'{tra:.2f}',f'{sia:.2f}'))
    print("\n")
    return

def var_level_evaluate(var_type_str,exp_size):
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^19}|{:^9}|{:^9}|{:^16}|{:^14}".format("Decompilers","Variables Identified/","Correct","Wrong","Variable in GT"   ,"Correct","Wrong","Type Inference","Size Inference"))
    print("{:^13}|{:^23}|{:^9}|{:^7}|{:^19}|{:^9}|{:^9}|{:^16}|{:^14}".format(""           ,"Variables in GT"      ,"Type"   ,"Type" ,"but not in Decomp","Size"   ,"Size" ,"Accuracy(%)"   ,"Accuracy(%)"))
    print(f"{'':-<127}")
    
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
        

        type_inf_acc = tp/max(tp+fp+fn,1) * 100
        size_inf_acc = c_sz/max(c_sz+w_sz,1) * 100
        print("{:^13}|{:>23}|{:>9}|{:>7}|{:>19}|{:>9}|{:>9}|{:>16}|{:>14}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, fn, c_sz, w_sz, f'{type_inf_acc:.2f}',f'{size_inf_acc:.2f}'))
    print("\n")
    
def func_level_evaluate(allow_complex=True, allow_primitives=True):
    
    print("{:^14}|{:^22}|{:^9}|{:^7}|{:^20}|{:^19}|{:^10}|{:^10}|{:^10}|{:^16}".format("Decompilers","Variables Identified/","Correct","Wrong","Variable in Decomp","Variable in GT"   ,"Coverage","Accuracy","Precision","False Positive"))
    print("{:^14}|{:^22}|{:^9}|{:^7}|{:^20}|{:^19}|{:^10}|{:^10}|{:^10}|{:^16}".format(""           ,"Variables in GT"      ,"Type"   ,"Type" ,"but not in GT"     ,"but not in Decomp","(%)"     ,"(%)"     ,"(%)"      ,"Rate(%)"))
    print(f"{'':-<146}")
    
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
                if has_complex(ground_truth_json[func]) and (not allow_complex):
                    continue
                
                if (not has_complex(ground_truth_json[func])) and (not allow_primitives):
                    continue
                
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
                    fn += len(gt_funcs[func])
                    continue
                
                for offset,_type in gt_funcs[func].items():
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

        total_decomp = tp+fp+tn
        total_gt = tp+fp+fn
        coverage = (tp+fp)/total_gt * 100
        accuracy = (tp)/total_gt * 100
        precision = (tp)/total_decomp * 100
        fpr = tn/total_decomp * 100
        
        
        print("{:^14}|{:>22}|{:>9}|{:>7}|{:>20}|{:>19}|{:>10}|{:>10}|{:>10}|{:>16}".format(decompiler,f'{tp+fp+tn}/{tp+fp+fn}', tp, fp, tn, fn, f'{coverage:.2f}',f'{accuracy:.2f}',f'{precision:.2f}',f'{fpr:.2f}'))
    print("\n")

def load_list(base_dir):
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

    return

def main():
    base_dir = f'binaries/{sys.argv[1]}' if len(sys.argv) > 1 else 'binaries/O0'
    base_dir = Path(base_dir)
    load_list(base_dir)
    
    print(f"Evaluating {len(GROUND_TRUTHS)} files with {sum(len(json.load(open(p))) for p in GROUND_TRUTHS)} functions.\n")
    print("="*135)
    
    
    print("Function Level Evaluations\n")
    
    print("[*] All Functions\n")
    func_level_evaluate(True,True)
 
    print("[*] Functions with only Primitive Types and Pointers\n")
    func_level_evaluate(False, True)

    print("[*] Functions with structs and arrays\n")
    func_level_evaluate(True, False)

    print("="*135)
    
    print("Type Level Evaluations\n")
    
    print("[*] Bool\n")
    var_level_evaluate('bool',1)
    
    print("[*] Char\n")
    var_level_evaluate('char',1)

    print("[*] Int\n")
    var_level_evaluate('int',4)

    print("[*] Long Long\n")
    var_level_evaluate('longlong',8)
    
    print("[*] Pointers\n")
    eval_pointers()

    print("[*] Arrays\n")
    eval_array()
    
    print("[*] Structs\n")
    eval_structs()
    

if __name__ == "__main__":
    main()