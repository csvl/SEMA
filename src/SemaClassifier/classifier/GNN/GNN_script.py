# GNN trainer, with federated learning, using flower library

import torch
import torch.nn as nn
import torch.nn.functional as F
# import torchvision
# import torchvision.transforms as transforms


from sklearn.model_selection import train_test_split,StratifiedShuffleSplit
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score , f1_score, balanced_accuracy_score
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, roc_auc_score
import seaborn as sns
import pandas as pd
import os
import glob

from torch_geometric.data import Batch
from torch_geometric.loader import DataLoader

import flwr as fl
from flwr.common import Metrics

import numpy as np
import logging
from collections import OrderedDict
from typing import List, Tuple
import progressbar

import argparse


# from ..Classifier import Classifier
# from .GINClassifier import GIN
# from .GINJKClassifier import GINJK
# from .GCNClassifier import GCN
# from .RGINClassifier import RanGIN
# from .RGINJKClassifier import RanGINJK
from GINJKFlagClassifier import GINJKFlag
# from .GNNExplainability import GNNExplainability

# import SVMClassifier from parent folder
import sys
sys.path.append("./SemaClassifier/classifier/")
from SVM.SVMClassifier import SVMClassifier
from SVM.SVMWLClassifier import SVMWLClassifier

from utils import gen_graph_data, read_gs_4_gnn, read_json_4_gnn, read_json_4_wl, read_mapping, read_mapping_inverse
import copy


DEVICE = torch.device("cpu")  # Try "cuda" to train on GPU

colours = ['\033[32m', '\033[33m', '\033[34m', '\033[35m','\033[36m', '\033[37m', '\033[90m', '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m']
reset = '\033[0m'
bold = '\033[01m'
disable = '\033[02m'
underline = '\033[04m'
reverse = '\033[07m'
strikethrough = '\033[09m'
invisible = '\033[08m'
default='\033[00m'
# print(
#     f"Training on {DEVICE} using PyTorch {torch.__version__} and Flower {fl.__version__}"
# )

def cprint(text,id):
    
    print(f'{colours[id%13]} {text}{default}')
    

def init_dataset(path, families, mapping, fam_idx, fam_dict, BINARY_CLASS):
    if path[-1] != "/":
        path += "/"
    print("Path: " + path)
    bar = progressbar.ProgressBar() #progressbar.ProgressBar(max_value=len(families))
    bar.start()
    original_path = path
    dataset = []
    dataset_wl = []
    label = []
    for family in families:
        path = original_path + family + '/'
        print("Subpath: " + f"{path}")
        if not os.path.isdir(path) :
            print("Dataset should be a folder containing malware classify by familly in subfolder")
            print("Path with error: " + path)
            exit(-1)
        else:
            filenames = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            # import pdb; pdb.set_trace()
            if len(filenames) > 1 and family not in fam_idx :
                fam_idx.append(family)
                fam_dict[family] = len(fam_idx) - 1
            for file in filenames:
                if file.endswith(".json"):
                    # edges, nodes, vertices, edge_labels = read_gs_4_gnn(file, mapping)
                    edges, nodes, vertices, edge_labels = read_json_4_gnn(file, mapping)
                    data = gen_graph_data(edges, nodes, vertices, edge_labels, fam_dict[family])
                    wl_graph = read_json_4_wl(file, mapping)
                    if len(edges) > 0:
                        if len(nodes) > 1:
                            dataset.append(data)
                            dataset_wl.append(wl_graph)
                        if BINARY_CLASS and len(nodes) > 1:
                            if family == 'clean':
                                label.append(family)
                            else:
                                label.append('malware')
                        else:
                            if len(nodes) > 1:
                                label.append(family)
    # import pdb; pdb.set_trace()
    bar.finish()
    return dataset, label, fam_idx, fam_dict, dataset_wl

def split_dataset_indexes(dataset, label):
    train_dataset = []
    y_train = []
    val_dataset = []
    y_val = []
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.4, random_state=54)
    # import pdb; pdb.set_trace()
    for train, test in sss.split(dataset, label):
        train_index = train
        val_index = test
    return train_index, val_index

def load_partition(n_clients,id,train_idx,test_idx,dataset,client=True,wl=False,label=None):
    """Load 1/(clients+1) of the training and test data."""

    server=False
    if not client and not wl:
        server = True
    
    # if client:
    #     assert id in range(n_clients)
    # else:
    #     assert id in range(n_clients+1)
    # if wl:
    #     assert label is not None

    n_train = int(len(train_idx) / (n_clients+1))
    n_test = int(len(test_idx) / (n_clients+1))

    train_partition = train_idx[id * n_train: (id + 1) * n_train]
    test_partition = test_idx[id * n_test: (id + 1) * n_test]    
    full_train_dataset, y_full_train, test_dataset, y_test = [], [], [], []
    for i in train_partition:
        full_train_dataset.append(dataset[i])
        if wl:
            y_full_train.append(label[i])
        else:
            y_full_train.append(dataset[i].y)
    for i in test_partition:
        test_dataset.append(dataset[i])
        if wl:
            y_test.append(label[i])
        else:
            y_test.append(dataset[i].y)
    cprint(f"client {id} : n_train {n_train}, start {id*n_train}, end {(id+1)*n_train}, client {client}, wl {wl}",id)
    cprint(f"client {id} : n_test {n_test}, start {id*n_test}, end {(id+1)*n_test}, client {client}, wl {wl}",id)
    return full_train_dataset,y_full_train, test_dataset,y_test

def one_epoch_train(model, train_loader, device, optimizer, criterion):
    model.train()
    loss_all = 0
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()
        output = model(data.x, data.edge_index, data.edge_attr, data.batch)
        loss = criterion(output, data.y)
        loss.backward()
        loss_all += data.num_graphs * loss.item()
        optimizer.step()
    return loss_all / len(train_loader.dataset)

def train(model, train_dataset, batch_size, epochs, device, id):
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    # scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.1, patience=10, verbose=True)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,
                              T_max = 42, # Maximum number of iterations.
                             eta_min = 1e-4) # Minimum learning rate.
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    for epoch in range(epochs):
        loss = one_epoch_train(model, train_loader, device, optimizer, criterion)
        scheduler.step()
        cprint(f"Epoch {epoch}, Loss: {loss}",id)
    cprint('--------------------FIT OK----------------',id)
    
    return model, {'loss': loss}

def test(model, test_dataset, batch_size, device,id):
    model.eval()
    correct, loss_all = 0, 0.0
    criterion = torch.nn.CrossEntropyLoss()
    y_pred = []
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    import pdb; pdb.set_trace()
    with torch.no_grad():
        for data in test_loader:
            data = data.to(device)
            output = model(data.x, data.edge_index, data.edge_attr, data.batch)
            loss = criterion(output, data.y).item()
            loss_all += loss * data.num_graphs
            pred = output.argmax(dim=1)
            correct += pred.eq(data.y).sum().item()
            for p in pred:
                y_pred.append(p.item())
    cprint('--------------------TEST OK----------------',id)
    return correct / len(test_loader.dataset), loss_all/len(test_loader.dataset), y_pred


def main(n_clients):
    # Load
    # Load the dataset
    # families = ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','sytro','wabot','RemcosRAT']
    families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
    batch_size = 32
    hidden = 64
    num_classes = len(families)
    num_layers = 5
    drop_ratio = 0.5
    residual = False
    id = n_clients

    # dataset, label, fam_idx, fam_dict = init_dataset("./databases/examples_samy/big_dataset/merged/traindata/CDFS", families, "./mapping.txt", [], {}, False)
    mapping = read_mapping("./mapping.txt")
    reversed_mapping = read_mapping_inverse("./mapping.txt")
    dataset, label, fam_idx, fam_dict, dataset_wl = init_dataset("./databases/examples_samy/BODMAS/01", families, reversed_mapping, [], {}, False)

    # Print datasets lengths:
    #print(f"GNN Dataset length: {len(dataset)}")
    #print(f"WL Dataset length: {len(dataset_wl)}")

    # Training and evaluation for k folds

    train_idx, test_idx = split_dataset_indexes(dataset, label)
    wl_full_train_dataset,wl_y_full_train, wl_test_dataset,wl_y_test = load_partition(n_clients=n_clients,id=id,train_idx=train_idx,test_idx=test_idx,dataset=dataset_wl,client=False,wl=True,label=label)
    cprint(f"Client {id} : datasets length  {len(wl_full_train_dataset)} {len(wl_test_dataset)}",id)    

    # graph kernel
    wl_model = SVMWLClassifier("./databases/examples_samy/BODMAS/01", 0.45, families)
    wl_model.train(dataset=wl_full_train_dataset, label=wl_y_full_train)
    wl_y_pred = wl_model.classify(dataset=wl_test_dataset)

    wl_acc = accuracy_score(wl_y_test, wl_y_pred)
    wl_prec = precision_score(wl_y_test, wl_y_pred, average=None)
    wl_rec = recall_score(wl_y_test, wl_y_pred, average=None)
    wl_f1 = f1_score(wl_y_test, wl_y_pred, average=None)
    wl_bal_acc = balanced_accuracy_score(wl_y_test, wl_y_pred)


    print()
    cprint("--------------------------------------------------",id)

    cprint(f"WL kernel Test accuracy: {wl_acc}",id)
    cprint(f"WL kernel Test precision: {list(wl_prec)}",id)
    cprint(f"WL kernel Test recall: {list(wl_rec)}",id)
    cprint(f"WL kernel Test f1: {list(wl_f1)}",id)
    cprint(f"WL kernel Test balanced accuracy: {wl_bal_acc}",id)

    print()
    cprint("--------------------------------------------------",id)


    #Dataset Loading
    families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
    mapping = read_mapping("./mapping.txt")
    reversed_mapping = read_mapping_inverse("./mapping.txt")
    dataset, label, fam_idx, fam_dict, dataset_wl = init_dataset("./databases/examples_samy/BODMAS/01", families, reversed_mapping, [], {}, False)
    train_idx, test_idx = split_dataset_indexes(dataset, label)
    full_train_dataset,y_full_train, test_dataset,y_test = load_partition(n_clients=n_clients,id=id,train_idx=train_idx,test_idx=test_idx,dataset=dataset)
    cprint(f"Client {id} : datasets length, {len(full_train_dataset)}, {len(test_dataset)}",id)

    #Model
    batch_size = 32
    hidden = 64
    num_classes = len(families)
    num_layers = 5
    drop_ratio = 0.5
    residual = False
    model = GINJKFlag(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers, drop_ratio=drop_ratio, residual=residual).to(DEVICE)

    # Test model
    accuracy, loss, y_pred = test(model, test_dataset, batch_size, DEVICE,id)
    cprint(f"GNN {id}: Evaluation accuracy & loss, {accuracy}, {loss}",id)

if __name__=="__main__":
    #Parse command line argument `nclients`
    parser = argparse.ArgumentParser(description="Flower")    
    parser.add_argument(
        "--nclients",
        type=int,
        default=1,
        choices=range(1, 10),
        required=False,
        help="Specifies the number of clients. \
        Picks partition 1 by default",
    )
    args = parser.parse_args()
    n_clients = args.nclients
    main(n_clients=n_clients)

    
