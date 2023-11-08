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
# print(
#     f"Training on {DEVICE} using PyTorch {torch.__version__} and Flower {fl.__version__}"
# )


def init_dataset(path, families, mapping, fam_idx, fam_dict, BINARY_CLASS):
    if path[-1] != "/":
        path += "/"
    print("Path: " + path)
    bar = progressbar.ProgressBar(max_value=len(families))
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

def train(model, train_dataset, batch_size, epochs, device):
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
        print(f"Epoch {epoch}, Loss: {loss}")
    print('--------------------FIT OK----------------')
    
    return model, {'loss': loss}

def test(model, test_dataset, batch_size, device):
    model.eval()
    correct, loss_all = 0, 0.0
    criterion = torch.nn.CrossEntropyLoss()
    y_pred = []
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
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
    print('--------------------TEST OK----------------')
    return correct / len(test_loader.dataset), loss_all/len(test_loader.dataset), y_pred

if __name__ == "__main__":
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

    # dataset, label, fam_idx, fam_dict = init_dataset("./databases/examples_samy/big_dataset/merged/traindata/CDFS", families, "./mapping.txt", [], {}, False)
    mapping = read_mapping("./mapping.txt")
    reversed_mapping = read_mapping_inverse("./mapping.txt")
    dataset, label, fam_idx, fam_dict, dataset_wl = init_dataset("./databases/examples_samy/BODMAS/01", families, reversed_mapping, [], {}, False)

    # Print datasets lengths:
    print(f"GNN Dataset length: {len(dataset)}")
    print(f"WL Dataset length: {len(dataset_wl)}")

    # Training and evaluation for k folds

    full_train_dataset, y_full_train, test_dataset, y_test = [], [], [], []
    wl_full_train_dataset, wl_y_full_train, wl_test_dataset, wl_y_test = [], [], [], []
    train_idx, test_idx = split_dataset_indexes(dataset, label)
    for i in train_idx:
        full_train_dataset.append(dataset[i])
        y_full_train.append(dataset[i].y)
        wl_full_train_dataset.append(dataset_wl[i])
        wl_y_full_train.append(label[i])
    for i in test_idx:
        test_dataset.append(dataset[i])
        y_test.append(dataset[i].y) 
        wl_test_dataset.append(dataset_wl[i])
        wl_y_test.append(label[i])

    # full_train_loader = DataLoader(full_train_dataset, batch_size=batch_size, shuffle=True)
    # test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    # split full_train into train and validation
    # train_dataset, y_train, val_dataset, y_val = split_dataset_indexes(full_train_dataset, y_full_train)
    # train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    # val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False) 

    model = GINJKFlag(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers, drop_ratio=drop_ratio, residual=residual)

    # import pdb; pdb.set_trace()

    # Train
    model = train(model, full_train_dataset, 1, 200, DEVICE)

    # Test
    test_acc, test_loss, y_pred = test(model, test_dataset, 8, DEVICE)

    test_prec = precision_score(y_test, y_pred, average=None)
    test_rec = recall_score(y_test, y_pred, average=None)
    test_f1 = f1_score(y_test, y_pred, average=None)
    test_bal_acc = balanced_accuracy_score(y_test, y_pred)

    print(f"Test accuracy: {test_acc}")
    print(f"Test precision: {list(test_prec)}")
    print(f"Test recall: {list(test_rec)}")
    print(f"Test f1: {list(test_f1)}")
    print(f"Test balanced accuracy: {test_bal_acc}")

    # graph kernel
    wl_model = SVMWLClassifier("./databases/examples_samy/BODMAS/01", 0.45, families)
    wl_model.train(dataset=wl_full_train_dataset, label=wl_y_full_train)
    wl_y_pred = wl_model.classify(dataset=wl_test_dataset)

    wl_acc = accuracy_score(wl_y_test, wl_y_pred)
    wl_prec = precision_score(wl_y_test, wl_y_pred, average=None)
    wl_rec = recall_score(wl_y_test, wl_y_pred, average=None)
    wl_f1 = f1_score(wl_y_test, wl_y_pred, average=None)
    wl_bal_acc = balanced_accuracy_score(wl_y_test, wl_y_pred)

    print(f"Test accuracy: {wl_acc}")
    print(f"Test precision: {list(wl_prec)}")
    print(f"Test recall: {list(wl_rec)}")
    print(f"Test f1: {list(wl_f1)}")
    print(f"Test balanced accuracy: {wl_bal_acc}")

    print()
    print("--------------------------------------------------")
    # side by side results:
    print(f"Test accuracy: {test_acc} vs {wl_acc}")
    print(f"Test precision: {list(test_prec)} vs {list(wl_prec)}")
    print(f"Test recall: {list(test_rec)} vs {list(wl_rec)}")
    print(f"Test f1: {list(test_f1)} vs {list(wl_f1)}")
    print(f"Test balanced accuracy: {test_bal_acc} vs {wl_bal_acc}")

    # import pdb; pdb.set_trace()