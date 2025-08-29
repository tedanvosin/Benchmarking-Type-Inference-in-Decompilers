file_o0 = set(open("file_eval_0", "r").readlines())
file_o1 = set(open("file_eval_2", "r").readlines())

overlap = file_o0.intersection(file_o1)
print("Overlap between file_eval_0 and file_eval_2:")
print(overlap)

print("Files unique to file_eval_0:")
O0_unique = sorted(set(file_o0) - set(file_o1))
with open('O0_unique','w') as f:
    for line in O0_unique:
        f.write(line)
