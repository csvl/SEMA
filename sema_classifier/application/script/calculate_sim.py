#!/usr/bin/env python3

import os
import argparse
import tempfile
N_GRAPH = 5


parser = argparse.ArgumentParser()
parser.add_argument("input", help="Name of the input file to classify")
parser.add_argument("sig", help="Name of the signature file")
args = parser.parse_args()

result_sim = open('res.txt','a')
tab_similarity = [0 for index in range(N_GRAPH)]

for sig_index in range(N_GRAPH):
    i = 0
    n_edges = 0
    f0 = open(args.sig,'r')
    f1 = open(args.input,'r')
    res = open('temp.gs','w')
    curr = 0
    in_ok = False
    for line in f0 :
        if in_ok and 't #' in line :
            break
        elif 't #' in line and sig_index == curr:
            res.write('t # '+str(i)+'\n')
            i += 1
            in_ok = True
        elif 't #' in line and sig_index != curr:
            curr +=1
        elif 'e ' in line and in_ok:
            n_edges +=1
            res.write(line)
        elif in_ok:
            res.write(line)
        else :
            pass
    f0.close()
    for line in f1 :
        if 't #' in line:
            res.write('t # '+str(i)+'\n')
            i += 1
        else :
            res.write(line)
    f1.close()
    res.close()
    os.system('build/gspan --input_file temp.gs -output_file temp2.gs --pattern --biggest_subgraphs 1 --threads 1 --timeout 5 --support 1.0')


    res2 = open('temp2.gs.t0','r')

    len_edges= []
    id = 0
    for line in res2 :
        if 't #' in line:
            len_edges.append(0)
        elif 'x: 0 1 ' in line:
            id += 1
        elif 'x: 0' in line :
            len_edges[id] = 0
            id += 1
        elif 'e ' in line :
            len_edges[id] += 1
        else :
            pass
    len_edges.append(0)
    


    res2.close()
    print('In original signature, there are '+str(n_edges)+' edges \n')
    print('After gspan, common subgraph has '+ str(max(len_edges))+' edges \n')
    print(len_edges)
    print('similarity :\n')
    try:
        print(max(len_edges)/n_edges)
        tab_similarity[sig_index] = max(len_edges)/n_edges
    except:
        tab_similarity[sig_index] = 0
    len_edges=[]
    os.remove('temp.gs')
    os.remove('temp2.gs.t0')
    
    
print(tab_similarity)
result_sim.write(args.input.split('/')[-1])
result_sim.write('\t')
result_sim.write(args.sig.split('/')[-1])
result_sim.write('\t')
result_sim.write(str(max(tab_similarity)))
result_sim.write('\n')
result_sim.close()
