import argparse
import ast
import time
import re
import json, csv
import claripy
import os
from datetime import datetime

#NOTE :
# Directory for testing have to respect following format :
# Dir|
#    |---family1/test/binary1
#                     binary2
#                     ......
#    |---family2/test/binary1
#                    ........

# Managing arguments
parser = argparse.ArgumentParser()
parser.add_argument("dir_input", help="Name of directory with all binary to classify")
parser.add_argument("dir_sig", help="Name of the directory with all gspan signatures")
parser.add_argument("out",help="Outfile name (csv)",default='out-'+datetime.now().strftime("%m-%d-%Y-%H:%M:%S")+'.csv')


#'autoit', 'delf', 'FeakerStealer', 'gandcrab', 'lamer', 'NetWire', 'nitol', 'RedLineStealer', 'RemcosRAT', 'sfone', 'shiz', 'sillyp2p', 'simbot', 'Sodinokibi', 'stormattack', 'sytro', 'upatre', 'wabot', 'bancteian', 'ircbot'
FAMILY = ['clean'] # 

args = parser.parse_args()
with open(args.out, 'w') as outfile:
        csvwriter = csv.writer(outfile, delimiter=',')

        header = ['name','true label','predicted label','similarity','all families','all scores']
        csvwriter.writerow(header)
        row = []
        #iterate through input family to classify
        for family in FAMILY:
            test_path = args.dir_input+'/'+family+'_1200/test/'
            if os.path.isdir(test_path):
                print("Current directory classified "+test_path)
                
                #Iterate through samples of the family to classify
                for test_input in os.listdir(test_path):
                    row = []
                    row.append(test_input)
                    row.append(family)
                    score = []
                    fam_tar = []
                   
                    #Iterate through signature to test in order to classify samples
                    for sig in os.listdir(args.dir_sig):
                    
                        os.system('python3 calculate_sim.py '+test_path+test_input+' '+args.dir_sig+'/'+sig)
                        
                        f = open('res.txt','r')
                        line = f.readline()
                        f.close()
                        temp = line.split('\t')
                        try:
                            score.append(float(temp[2]))
                        except:
                            score.append(0)
                        
                        fam_tar.append(sig.split('_')[-1][:-3])
                        try:
                            os.remove('res.txt')
                        except:
                            pass
                    
                    max_score = max(score)
                    best_fam = fam_tar[score.index(max_score)]
                    row.append(best_fam)
                    row.append(max_score)
                    row.append(fam_tar)
                    row.append(score)
                    csvwriter.writerow(row)
