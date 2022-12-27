#!/usr/bin/env python3

from graphviz import Digraph
import argparse


class ReverseGspan:
    def __init__(self) -> None:
        pass

    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--map", help="Mapping file used to reverse label of gspan graph"
        )
        parser.add_argument("--out", help="Name of the output file")
        parser.add_argument("gsp_file", help="gspan file to reverse back")
        args = parser.parse_args()

        if args.map:
            map_name = args.map
        else:
            map_name = "mapping.txt"

        gspan_file = args.gsp_file

        if args.out:
            out = args.out
        else:
            out = gspan_file.split(".")[0]

        mapping = {}

        map_file = open(map_name, "r")
        for line in map_file:
            tab = line.split("\n")[0].split(" ")
            print(tab)
            mapping[tab[0]] = tab[1]

        graph_gspan = open(gspan_file, "r")

        dot = None
        id = 0
        for line in graph_gspan:
            tab = line.split("\n")[0]
            if "t #" in tab:
                if dot:
                    dot.render("reverse/" + out + "_" + str(id) + ".gv", view=True)
                    id = id + 1
                # new graph
                dot = Digraph(comment=out + "_" + str(id))
            info = tab.split(" ")
            if "v" in tab:
                dot.node(info[1], mapping[info[2]])
            elif "e" in tab:
                dot.edge(info[1], info[2], label=info[3])
            else:
                pass
        dot.render("reverse/" + out + "_" + str(id) + ".gv", view=True)
