f0 = open("O0_file_list",'r').readlines()
f1 = open("O2_file_list",'r').readlines()

cnt=0
out_list = open("file_list.txt",'w')
for file in f0:
    if file in f1:
        out_list.write(file)        
        print(file)
        cnt+=1
        
print(f"Total files:{cnt}")