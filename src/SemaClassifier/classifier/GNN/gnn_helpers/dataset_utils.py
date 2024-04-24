# GNN trainer, with federated learning, using flower library

import torch

from sklearn.model_selection import train_test_split,StratifiedShuffleSplit

import pandas as pd
import os

from collections import defaultdict
import progressbar

from .utils import gen_graph_data, read_gs_4_gnn, read_mapping, read_mapping_inverse, read_gs


    
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
                # import pdb; pdb.set_trace()
                if file.endswith(".gs"):
                    edges, nodes, vertices, edge_labels = read_gs_4_gnn(file, mapping)
                    wl_graph = read_gs(file, mapping)
                    if len(edges) > 0:
                        data = gen_graph_data(edges, nodes, vertices, edge_labels, fam_dict[family])
                        # import pdb; pdb.set_trace()
                        if len(nodes) > 1:
                            dataset.append(data)
                        if len(wl_graph.vertices) > 1:
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
    return dataset, label, fam_idx, fam_dict #, dataset_wl

def temporal_init_dataset(path, families, mapping, fam_idx, fam_dict, BINARY_CLASS, name_map):
    if path[-1] != "/":
        path += "/"
    print("Path: " + path)
    bar = progressbar.ProgressBar() #progressbar.ProgressBar(max_value=len(families))
    bar.start()
    original_path = path
    dataset = []
    dataset_wl = []
    label = []
    dataset_dict = defaultdict(list)
    dataset_dict_wl = defaultdict(list)
    names_dict = defaultdict(list)
    for family in families:
        path = original_path + family + '/'
        print("Subpath: " + f"{path}")
        if not os.path.isdir(path) :
            print("Dataset should be a folder containing malware classify by familly in subfolder")
            print("Path with error: " + path)
            exit(-1)
        else:
            if family == "cleanware":
                filenames = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            else:
                # fdf = pd.read_csv(f'./gnn_helpers/filtered_sorted_metadata.csv')
                fdf = pd.read_csv(f'./gnn_helpers/bodmas2_sorted_metadata.csv')
                # fdf = pd.read_csv(f'./fam_sorted/{family}_sorted_metadata.csv')
                filenames_sorted = fdf["sha"].values
                filenames = [os.path.join(path, f"{name_map[sample]}") for sample in filenames_sorted if os.path.isfile(os.path.join(path, f"{name_map[sample]}"))]
            if len(filenames) > 1 and family not in fam_idx :
                fam_idx.append(family)
                fam_dict[family] = len(fam_idx) - 1
            for file in filenames:
                if file.endswith(".gs"):
                    edges, nodes, vertices, edge_labels = read_gs_4_gnn(file, mapping)
                    wl_graph = read_gs(file, mapping)
                    if len(edges) > 0:
                        data = gen_graph_data(edges, nodes, vertices, edge_labels, fam_dict[family])
                        if len(nodes) > 1:
                            dataset.append(data)
                            dataset_wl.append(wl_graph)
                            dataset_dict[family].append(data)
                            dataset_dict_wl[family].append(wl_graph)
                            names_dict[family].append(file)
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
    return dataset_dict, dataset, label, fam_idx, fam_dict#, dataset_wl, dataset_dict_wl

def hard_temporal_init_dataset(path, families, mapping, fam_idx, fam_dict, BINARY_CLASS, name_map):
    if path[-1] != "/":
        path += "/"
    print("Path: " + path)
    bar = progressbar.ProgressBar() #progressbar.ProgressBar(max_value=len(families))
    bar.start()
    original_path = path
    dataset = []
    dataset_wl = []
    label = []
    dataset_dict = defaultdict(list)
    dataset_dict_wl = defaultdict(list)
    names_dict = defaultdict(list)
    for family in families:
        path = original_path + family + '/'
        print("Subpath: " + f"{path}")
        if not os.path.isdir(path) :
            print("Dataset should be a folder containing malware classify by familly in subfolder")
            print("Path with error: " + path)
            exit(-1)
        else:
            fdf = pd.read_csv(f'./gnn_helpers/filtered_sorted_metadata.csv')
            samples = fdf["sha"].values
            length = len(samples)
            filenames = [(os.path.join(path, f"{name_map[samples[i]]}"), i) for i in range(length) if os.path.isfile(os.path.join(path, f"{name_map[samples[i]]}"))]
            if len(filenames) > 1 and family not in fam_idx :
                fam_idx.append(family)
                fam_dict[family] = len(fam_idx) - 1
            for file, idx in filenames:
                if file.endswith(".gs"):
                    edges, nodes, vertices, edge_labels = read_gs_4_gnn(file, mapping)
                    wl_graph = read_gs(file, mapping)
                    if len(edges) > 0:
                        data = gen_graph_data(edges, nodes, vertices, edge_labels, fam_dict[family])
                        if len(nodes) > 1:
                            dataset.append((data, idx))
                            dataset_wl.append((wl_graph, idx))
                            dataset_dict[family].append(data)
                            dataset_dict_wl[family].append(wl_graph)
                            names_dict[family].append((file, idx))
                        if BINARY_CLASS and len(nodes) > 1:
                            if family == 'clean':
                                label.append(family)
                            else:
                                label.append('malware')
                        else:
                            if len(nodes) > 1:
                                label.append(family)
    sorted_list = sorted(dataset, key=lambda x: x[1])
    sorted_list_wl = sorted(dataset_wl, key=lambda x: x[1])
    output_d = []
    output_d_wl = []
    output_label = []
    for tup in sorted_list:
        output_d.append(tup[0])
        output_label.append(fam_idx[tup[0].y.item()])
    for tup_wl in sorted_list_wl:
        output_d_wl.append(tup_wl[0])
        # output_label.append(fam_idx[tup[0].y.item()])
    bar.finish()
    return dataset_dict, output_d, output_label, fam_idx, fam_dict#, output_d_wl, dataset_dict_wl

def hard_temporal_split_train_test(dataset, ratio, names_dict=None):
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    train_names = []
    test_names = []
    split_index = int(ratio * len(dataset))
 
    train_dataset.extend(dataset[:split_index])
    test_dataset.extend(dataset[split_index:])

    for e_tr in train_dataset:
        y_train.append(e_tr.y.item())
    for e_ts in test_dataset:
        y_test.append(e_ts.y.item())
    
    return train_dataset, y_train, test_dataset, y_test

def hard_temporal_split_train_test_wl(dataset, ratio, label): # For SEMA wl kernel svm model
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    train_names = []
    test_names = []
    split_index = int(ratio * len(dataset))
 
    train_dataset.extend(dataset[:split_index])
    test_dataset.extend(dataset[split_index:])

    y_train.extend(label[:split_index])
    y_test.extend(label[split_index:])

    return train_dataset, y_train, test_dataset, y_test

def temporal_split_train_test(dataset_dict, ratio):
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    for f in dataset_dict:
        data = dataset_dict[f]
        split_index = int(ratio * len(data))

        train_dataset.extend(data[:split_index])
        test_dataset.extend(data[split_index:])

    for e_tr in train_dataset:
        y_train.append(e_tr.y.item())
    for e_ts in test_dataset:
        y_test.append(e_ts.y.item())
    
    return train_dataset, y_train, test_dataset, y_test

def temporal_split_train_test_wl(dataset_dict, ratio, label): # For SEMA wl kernel svm model
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    for f in dataset_dict:
        data = dataset_dict[f]
        split_index = int(ratio * len(data))

        train_dataset.extend(data[:split_index])
        test_dataset.extend(data[split_index:])
        y_train.extend([f for _ in data[:split_index]])
        y_test.extend([f for _ in data[split_index:]])
    
    return train_dataset, y_train, test_dataset, y_test

def split_dataset_indexes(dataset, label):
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
    for train, test in sss.split(dataset, label):
        train_index = train
        val_index = test
    return train_index, val_index

def cross_val_split_dataset_indexes(dataset, label, k):
    sss = StratifiedShuffleSplit(n_splits=k, test_size=0.3, random_state=42)
    train_indexes = []
    val_indexes = []
    for train, test in sss.split(dataset, label):
        train_indexes.append(train)
        val_indexes.append(test)
    return train_indexes, val_indexes

def get_datasets(dataset, trn_idx, tst_idx):
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    for i in trn_idx:
        train_dataset.append(dataset[i])
        y_train.append(dataset[i].y.item())
    for i in tst_idx:
        test_dataset.append(dataset[i])
        y_test.append(dataset[i].y.item())
    return train_dataset, y_train, test_dataset, y_test

def get_folds(dataset, train_indexes, val_indexes):
    train_folds = []
    y_train_folds = []
    val_folds = []
    y_val_folds = []
    for train_idx_list in train_indexes:
        split = []
        y_split = []
        for i in train_idx_list:
            split.append(dataset[i])
            y_split.append(dataset[i].y.item())
        train_folds.append(split)
        y_train_folds.append(y_split)
    for val_idx_list in val_indexes:
        vsplit = []
        y_vsplit = []
        for j in val_idx_list:
            vsplit.append(dataset[j])
            y_vsplit.append(dataset[j].y.item())
        val_folds.append(vsplit)
        y_val_folds.append(y_vsplit)
    return train_folds, y_train_folds, val_folds, y_val_folds