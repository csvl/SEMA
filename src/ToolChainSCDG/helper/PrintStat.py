#!/usr/bin/env python3

from prettytable import PrettyTable
import os
from os import walk
import csv


class PrintStat:
    def __init__(self):
        pass

    def run(self):
        csv_file = open("../res/raw.csv", "w", newline="")
        writer = csv.writer(csv_file)

        tab = PrettyTable(
            [
                "Name",
                "method",
                "time",
                "z3",
                "calls",
                "nodes",
                "edges",
                "density",
                "conn comp",
                "str con comp",
                "useless",
                "usefull",
            ]
        )

        DIR = "../res/malware-inputs/time_eval_samples/"
        PATH_RESULT = "../output/save-SCDG/"
        families = [
            "autoit",
            "bancteian",
            "delf",
            "ircbot",
            "shiz",
            "simbot",
            "stormattack",
            "sytro",
            "tufik",
            "wabot",
        ]

        writer.writerow(
            [
                "Name",
                "method",
                "time",
                "z3",
                "calls",
                "nodes",
                "edges",
                "density",
                "conn comp",
                "str con comp",
                "useless",
                "usefull",
            ]
        )

        Dataset = []

        # Get all names of malwares in list_file
        for fam in families:
            list_file = []
            for (dirpath, dirnames, filenames) in walk(DIR + fam):
                list_file.extend(filenames)
                break

            for mal in list_file:
                # z3 30
                # check if experiment results exist
                for t in ["600", "1800", "3600"]:
                    try:
                        path = PATH_RESULT + mal + "_SCDG_" + str(t) + ".txt"
                        os.stat(path)

                        os.system("python3 EvalStatSCDG.py --name " + path)

                        f = open(
                            "../../test/some-test/SCDG_"
                            + mal
                            + "_SCDG_"
                            + str(t)
                            + ".txt.info",
                            "r",
                        )

                        # from time import sleep
                        # sleep(5)
                        lines = f.readlines()

                        result = 12 * [0]
                        result[0] = mal + "_" + fam + "_" + str(t)
                        result[1] = "BFS"
                        result[2] = t
                        result[3] = "30"
                        i = 4

                        for l in lines:
                            temp = l.split(":")
                            result[i] = temp[1].replace(" ", "").replace("\n", "")
                            i += 1
                        f.close()

                        tab.add_row(result)
                        Dataset.append(result)
                        writer.writerow(result)
                    except:
                        result = 12 * [0]
                        result[0] = mal + "_" + fam + "_" + str(t)
                        result[1] = "DFS"
                        result[2] = t
                        result[3] = "60"
                        tab.add_row(result)

                # z3 30
                # check if experiment results exist
                """for t in ['']:
                    try :
                        path = '../output/save-SCDG_CBFS/'+mal+'_SCDG'+str(t)+'.txt'
                        os.stat(path)
                        
                        os.system('python3 eval_stat_SCDG.py --name '+path)
                        
                        f = open('../../test/some-test/SCDG_'+mal+'_SCDG'+str(t)+'.txt.info','r')
                        
                        #from time import sleep
                        #sleep(5)
                        lines = f.readlines()
                        
                        result = 9*[0]
                        result[0] = mal+'_'+fam+'_'+str(t)
                        result[1] = 'CBFS'
                        result[2] = '60'
                        i = 3
                        
                        for l in lines : 
                            temp = l.split(':')
                            result[i] = temp[1].replace(' ','').replace('\n','')
                            i += 1
                        f.close()
                        tab.add_row(result)
                    except :
                        result = 9*[0]
                        result[0] = mal+'_'+fam+'_'+str(t)
                        result[1] = 'CBFS'
                        result[2] = '60'
                        tab.add_row(result)"""

                # z3 60
                # check if experiment results exist
                for t in ["600", "1800", "3600"]:
                    try:
                        path = (
                            "../output/save-SCDG_z3/" + mal + "_SCDG_" + str(t) + ".txt"
                        )
                        os.stat(path)
                        os.system("python3 eval_stat_SCDG.py --name " + path)

                        f = open(
                            "../../test/some-test/SCDG_"
                            + mal
                            + "_SCDG_"
                            + str(t)
                            + ".txt.info",
                            "r",
                        )
                        lines = f.readlines()

                        result = 12 * [0]
                        result[0] = mal + "_" + fam + "_" + str(t)
                        result[1] = "BFS"
                        result[2] = t
                        result[3] = "60"
                        i = 4
                        for l in lines:
                            temp = l.split(":")
                            result[i] = temp[1].replace(" ", "").replace("\n", "")
                            i += 1
                        f.close()

                        tab.add_row(result)
                        Dataset.append(result)
                        writer.writerow(result)
                    except:
                        result = 12 * [0]
                        result[0] = mal + "_" + fam + "_" + str(t)
                        result[1] = "BFS"
                        result[2] = t
                        result[3] = "60"
                        tab.add_row(result)

        print(tab)
