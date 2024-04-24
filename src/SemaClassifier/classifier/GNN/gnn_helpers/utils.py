import json
import pickle
import os
from glob import glob
import numpy as np
import progressbar
import torch
from torch_geometric.data import Data
import torch.nn.functional as F
from torch_geometric.data import Batch
from grakel import Graph
from torch.utils.data import Dataset

import networkx as nx
import collections
import dill

colours = ['\033[32m', '\033[33m', '\033[34m', '\033[35m','\033[36m', '\033[37m', '\033[90m', '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m']
reset = '\033[0m'
bold = '\033[01m'
disable = '\033[02m'
underline = '\033[04m'
reverse = '\033[07m'
strikethrough = '\033[09m'
invisible = '\033[08m'
default='\033[00m'

def cprint(text,id):
    print(f'{colours[id%13]} {text}{default}')

def save_model(object, path):
        with open(path, 'wb+') as output:
            dill.dump(object, output)

def load_model(path):
    with open(path, 'rb') as inp:
        print(path)
        print(inp)
        return dill.load(inp)

# Process the graph data and convert to a PyG Data object.
def gen_graph_data(edges, nodes, vertices, edge_labels, label):
    edges = list(edges)
    x = torch.tensor([torch.tensor(nodes[v]) for v in vertices])
    x = x.unsqueeze(-1)
    edge_attr = torch.tensor([int(str(edge_labels[e])) for e in edges]) # 1st version
    # edge_attr = torch.cat([edge_labels[key].unsqueeze(0) for key in edges], dim=0) # vector version
    num_nodes = len(vertices)
    y = torch.tensor([label])
    edge_index=torch.tensor(edges, dtype=torch.long)

    if (len(edge_index.size()) == 2):
        edge_index = edge_index.transpose(0, 1)
        
    # correct edge_attr dimensions
    edge_attr = edge_attr.to(torch.float32)
    edge_attr = edge_attr.unsqueeze(-1) # for 1st version

    data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, num_nodes=num_nodes, y=y)
    return data

def read_gs_4_gnn(path, mapping, lonely=True):
    f = open(path,'r')
    vertices = {}
    nodes = {}
    edges = {}
    edge_labels = {}
    c_edges = 1
    for line in f:
        if line.startswith("t"):
            pass
        if line.startswith("v"):
            sp = line.split(" ")
            v = int(sp[1])
            vertices[v] = []
            v_label = int(sp[2])
            # nodes[v] = mapping[v_label] 
            nodes[v] = v_label
        if line.startswith("e"):
            #self.log.info(line)
            sp = line.split(" ")
            v1 = int(sp[1])
            v2 = int(sp[2])
            e_label = int(sp[3].replace('\n',''))

            if tuple((v1,v2)) not in edges:
                edges[tuple((v1,v2))] = 1
                edge_labels[tuple((v1,v2))] = e_label

            c_edges = c_edges + 1
            vertices[v1].append(v2)
            vertices[v2].append(v1)

    if not lonely:
        #STUFF below to delete lonely nodes
        de = []
        count = 0
        vertices_ok = {}
        nodes_ok = {}
        map_clean = {}
        # find index of lonely node
        for key in vertices:
            if not vertices[key]:
                de.append(key)
            else:
                map_clean[key] = count
                count = count +1
        #delete them
        for key in de:
            del vertices[key]

        for key in vertices:
            local_dic = {}
            for v in vertices[key]:
                local_dic[map_clean[v]] = 1.0
            
            #self.log.info(local_dic)
            vertices_ok[map_clean[key]] = local_dic
            nodes_ok[map_clean[key]] = nodes[key]

        # if len(vertices_ok) <= 1:
        #     self.log.info(vertices_ok)

        G = edges, nodes_ok, vertices_ok, edge_labels
    else:
        G = edges, nodes, vertices, edge_labels
    f.close()
    return G

def read_gs(path,mapping,lonely=True):
    f = open(path,'r')
    vertices = {}
    nodes = {}
    edges = {}
    edge_labels = {}
    c_edges = 1
    for line in f:
        if line.startswith("t"):
            pass
        if line.startswith("v"):
            sp = line.split(" ")
            v = int(sp[1])
            vertices[v] = []
            v_label = int(sp[2])
            # nodes[v] = mapping[v_label] 
            nodes[v] = v_label
        if line.startswith("e"):
            #self.log.info(line)
            sp = line.split(" ")
            v1 = int(sp[1])
            v2 = int(sp[2])
            e_label = sp[3].replace('\n','')
            edges[tuple((v1,v2))] = 1
            edge_labels[tuple((v1,v2))] = e_label
            c_edges = c_edges + 1
            vertices[v1].append(v2)
            vertices[v2].append(v1)
    
    if not lonely:
        #STUFF below to delete lonely nodes
        de = []
        count = 0
        vertices_ok = {}
        nodes_ok = {}
        map_clean = {}
        # find index of lonely node
        for key in vertices:
            if not vertices[key]:
                de.append(key)
            else:
                map_clean[key] = count
                count = count +1
        #delete them
        for key in de:
            del vertices[key]

        for key in vertices:
            local_dic = {}
            for v in vertices[key]:
                local_dic[map_clean[v]] = 1.0
            
            #self.log.info(local_dic)
            vertices_ok[map_clean[key]] = local_dic
            nodes_ok[map_clean[key]] = nodes[key]

        # if len(vertices_ok) <= 1:
        #     self.log.info(vertices_ok)
        G = Graph(vertices_ok,node_labels=nodes_ok,edge_labels=edge_labels)
    else:
        
        G = Graph(vertices,node_labels=nodes,edge_labels=edge_labels)
    f.close()
    return G

def read_mapping(path):
    map_file = open(path,'r')
    mapping = {}
    for line in map_file:
        tab = line.split('\n')[0].split(' ')
        mapping[int(tab[0])] = tab[1]
    map_file.close()
    return mapping

def read_mapping_inverse(path):
        map_file = open(path,'r')
        mapping = {}
        for line in map_file:
            tab = line.split('\n')[0].split(' ')
            mapping[tab[1]] = int(tab[0])
        map_file.close()
        return mapping