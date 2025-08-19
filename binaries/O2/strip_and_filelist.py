#!/usr/bin/env python3
import os, shutil, subprocess

src, dst = "binaries_debug", "binaries_stripped"
os.makedirs(dst, exist_ok=True)

with open("file_list.txt", "w") as f:
    for fname in os.listdir(src):
        path = os.path.join(src, fname)
        if os.path.isfile(path):
            shutil.copy(path, dst)
            subprocess.run(["strip", "--strip-debug", os.path.join(dst, fname)])
            f.write(fname + "\n")
