#!/usr/bin/env python3
import glob,os
import argparse
from GraphBuilder import *


class MergeGspan:
    def __init__(self):
        pass

    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--out", help="Name of the output file")
        parser.add_argument("--c", help="create gspan file from SCDG",type=bool)
        parser.add_argument("dir", help="directory with gspan files to merge")
        parser.add_argument("--fam",help="malware family",default="stub")
        args = parser.parse_args()

        if args.out:
            out = args.out
        else:
            out = 'SCDG_mirai_global.gs'

        os.chdir(args.fam)

        if args.c :
            for file in glob.glob("*SCDG.txt") :
                data = []
                f = open(file,'r')
                for line in f:
                    #print(string)

                    a = line.replace('\n','')
                    b = a.replace('\t','')
                    c = b.strip()
                    d = c.replace("<","'<").replace(">",">'").replace("'<=","<=").replace(">' ","> ").replace("''","'")
                    data.append(eval(d))
                f.close()
                g =GraphBuilder(name=file,mapping='../res/mapping.txt',merge_call=True,comp_args=False,min_size=0,ignore_zero=True,odir='../../'+args.fam+'_gs',get_info=False)
                g.build_graph(data)

        print(args.fam)
        print(args.dir)

        os.chdir('../'+args.dir)
        id_graph = 0
        res = open(out,'w')

        for file in glob.glob("*.gs") :
            print(file)
            f = open(file,'r')
            fstat = os.stat(file)
            if fstat.st_size > 150 :
                for line in f :
                    if 't #' in line:
                        res.write('t # '+str(id_graph)+'\n')
                        id_graph += 1
                    else :
                        res.write(line)
            f.close()
        res.close()
