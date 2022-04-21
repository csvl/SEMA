import glob
import os
import argparse
import seaborn as sns
import matplotlib.pyplot as plt

#Script to compute similarity between signatures obtained thanks to Gspan 

GSPAN_PATH = '../../build/gspan'

def calculate_sim(in_file,sig):
    N_GRAPH = 5
    tab_similarity = [0 for index in range(N_GRAPH)]

    for sig_index in range(N_GRAPH):
        i = 0
        n_edges = 0
        f0 = open(sig,'r')
        f1 = open(in_file,'r')
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
        stop=0
        for line in f1 :
            if 't #' in line:
                if stop:
                    break
                res.write('t # '+str(i)+'\n')
                i += 1
                stop +=1
            else :
                res.write(line)
        f1.close()
        res.close()

        os.system(GSPAN_PATH+' --input_file temp.gs -output_file temp2.gs --pattern --biggest_subgraphs 1 --threads 1 --timeout 5 --support 1.0')

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
        return max(tab_similarity)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", help="Directory containing signatures obtained with Gspan")
    args = parser.parse_args()

    all_names = glob.glob(args.directory+'/*_sig.gs')
    names = []
    table = [[] for i in range(len(all_names))]
    i = 0

    for signature1 in all_names:
            
        for signature2 in all_names:
            print(signature1+'------------------------------ '+signature2)
            out = round(calculate_sim(signature1,signature2),2)
            table[i].append(out)
        names.append(signature1.split('_')[-2].replace(args.directory,''))
        i+=1
        
    sns.heatmap(table,annot=table,fmt="",xticklabels=names,yticklabels=names,cmap='RdYlGn',linewidths=0.30)
    plt.show()
