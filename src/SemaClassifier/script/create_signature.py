#!/usr/bin/env python3

import os
import argparse
import tempfile
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("input", help="Name of the input file with all graphs of a family to mine")
parser.add_argument("--out", help="Name of the output file with signature",default='out-'+datetime.now().strftime("%m-%d-%Y-%H:%M:%S")+'.gs')
parser.add_argument("--support", help="support arg of gspan", default=0.75)
args = parser.parse_args()

os.system('build/gspan --input_file '+args.input+' --output_file '+args.out+' --pattern --biggest_subgraphs 5 --threads 5 --timeout 120 --support '+str(args.support))

files = []
for i in range(5):
    if os.path.isfile(args.out+'.t'+str(i)):        
        file = open(args.out+'.t'+str(i),'r')
        files.append(file)

sig = open(args.out,'w')
buf_temp_f =[]
len_file = []
n_file = 0
counter = 0
for file in files :
    for line in file :
        if 't #' in line:
            buf_temp_f.append([])
            counter = 0
            #f_temp_f[n_file].write('t # '+str(n_file))
        elif 'x: ' in line:
            len_file.append(counter)
            n_file += 1
        elif 'e ' in line :
            buf_temp_f[n_file].append(line)
            counter +=1
        elif 'v ' in line :
            buf_temp_f[n_file].append(line)
        else :
            pass
for f in files:
    f.close()
    if os.path.isfile(f.name):
        os.remove(f.name)

N_MAX = 5
for i in range(N_MAX):
    id_max = len_file.index(max(len_file))
    sig.write('t # '+str(i)+'\n')
    sig.write(''.join(l for l in buf_temp_f[id_max]))
    len_file[id_max] = -1
sig.close()
