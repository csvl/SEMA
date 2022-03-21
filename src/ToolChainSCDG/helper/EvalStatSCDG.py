#!/usr/bin/env python3
import argparse
from GraphBuilder import *


class EvalStatSCDG:
    """
    TODO
    """

    def __init__(self, dir="../output/save-SCDG/"):
        self.dir = dir

    def run():
        # Managing arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("--name", help="Name of SCDG file")

        args = parser.parse_args()
        short_name = args.name.split("/")[2]

        short_name.split("_")[0] + "_SCDG_"

        calls = {}

        data = []
        f = open(args.name, "r")
        for line in f:
            # print(line)
            a = line.replace("\n", "")
            b = a.replace("\t", "")
            c = b.strip()
            d = (
                c.replace("<", "'<")
                .replace(">", ">'")
                .replace("'<=", "<=")
                .replace(">' ", "> ")
            )
            data.append(eval(d))

        # data = [eval(line.replace('\n','')) for line in f]
        # data=data[1]
        print("Number of traces : " + str(len(data)))
        for s in data:
            for c in s:
                if c["name"] in calls:
                    calls[c["name"]] = calls[c["name"]] + 1
                else:
                    calls[c["name"]] = 1
        f.close()

        f = open("some_test/SCDG_" + short_name + ".info", "w")

        f.write("Number of different calls : " + str(len(calls.keys())) + "\n")
        f.close()
        g = GraphBuilder(
            name=short_name,
            mapping="mapping.txt",
            merge_call=True,
            comp_args=False,
            min_size=0,
            ignore_zero=True,
            odir="./some_test",
            get_info=True,
        )
        g.build_graph(data)
        print("Number of different calls : " + str(len(calls.keys())))
        print(calls)
