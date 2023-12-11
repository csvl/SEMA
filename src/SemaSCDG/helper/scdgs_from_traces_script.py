# Python script that reads inter_SCDG.json file in a list_obj, gets all traces with list_obj[exec_number][trace_id]['trace'] and appends it to a list scdg_fin to creates scdgs using the build_graph function from GraphBuilder.py

import json
import os
import sys
import argparse

from GraphBuilder import *

disjoint_union = False
min_size = 3
not_comp_args = False
not_ignore_zero = False
three_edges = True
verbose = False

ds_path = "../../output/runs/100/"
families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
format_out_json = False

# Reads all inter_SCDG.json files in the ds_path/<file> and creates a list of all traces
def get_traces(fam_path, sample):
    list_obj = []
    scdg_fin = []
    ofilename = fam_path + sample + "/inter_SCDG.json"
    # Check if file exists
    if os.path.isfile(ofilename):
        # Read JSON file
        with open(ofilename) as fp:
            list_obj = json.load(fp)
        for i in range(len(list_obj)):
            for j in list_obj[i].keys():
                if j != 'sections':
                    scdg_fin.append(list_obj[i][j]['trace'])
        return scdg_fin


for fam in families:
    fam_path = ds_path + fam + "/"
    for sample in os.listdir(fam_path):
        # Creates a list of all traces from all families
        basename_dir = os.path.basename(fam_path)
        # import pdb; pdb.set_trace()
        # Creates folder for sample:
        if not os.path.exists('../../databases/examples_samy/three_edge_scdg_gs/' + fam + '/' + sample):
            os.makedirs('../../databases/examples_samy/three_edge_scdg_gs/' + fam + '/' + sample)
        g = GraphBuilder(
            name=sample,
            mapping="../../mapping.txt",
            merge_call=(not disjoint_union),
            comp_args=(not not_comp_args),
            min_size=min_size,
            ignore_zero=(not not_ignore_zero),
            three_edges=three_edges,
            odir='../../databases/examples_samy/three_edge_scdg_gs/',
            verbose=verbose,
            familly=fam,
        )
        scdg_fin = get_traces(fam_path, sample)
        if scdg_fin != None:
            # print(fam_path + sample)
            # Creates scdgs from the traces
            g.build_graph(scdg_fin, format_out_json=format_out_json)
