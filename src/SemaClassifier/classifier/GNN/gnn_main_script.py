import time

from matplotlib import pyplot as plt
import gnn_helpers.dataset_utils as dataset_utils
import argparse
import os
import torch
import numpy as np
import flwr as fl
from gnn_helpers.utils import read_mapping, read_mapping_inverse, save_model, load_model, cprint
import copy
import json

from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score , f1_score, balanced_accuracy_score

from models.GINEClassifier import GINE
from models.GINJKClassifier import GINJK
from models.GINMLPClassifier import GINMLP

from torch_geometric.loader import DataLoader

import pandas as pd
import seaborn as sns

from gnn_helpers.metrics_utils import *
from gnn_helpers.models_training import *
from gnn_helpers.models_tuning import *

DEVICE: str = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")

BATCH_SIZE_TEST=32

fam_idx = {}

def init_all_datasets(path, families, mapping, reversed_mapping):

    id = 1

    ### Dataset without temportal constraint
    dataset, label, fam_idx, fam_dict = dataset_utils.init_dataset(path, families, reversed_mapping, [], {}, False)
    train_idx, test_idx = dataset_utils.split_dataset_indexes(dataset, label)
    full_train_dataset,y_full_train, test_dataset, y_test = dataset_utils.get_datasets(dataset, train_idx, test_idx)

    ### Dataset with temportal constraint
    # with open("./gnn_helpers/rev_bodmas_mapping_hash.json", "r") as fp:
    # with open("./gnn_helpers/rev_bodmas2_mapping.json", "r") as fp:
    #     name_map = json.load(fp)
    # dataset_dict, dataset, label, fam_idx, fam_dict = dataset_utils.temporal_init_dataset(path, families, reversed_mapping, [], {}, False, name_map)
    # full_train_dataset,y_full_train, test_dataset, y_test = dataset_utils.temporal_split_train_test(dataset_dict, 0.7)

    cprint(f"GNN {id} : datasets length, {len(dataset)}, {len(full_train_dataset)}, {len(test_dataset)}",id)

    # # Validation dataset
    # trn_idx, val_idx = dataset_utils.split_dataset_indexes(full_train_dataset, y_full_train)
    # train_dataset, y_train, val_dataset, y_val = dataset_utils.get_datasets(full_train_dataset, trn_idx, val_idx)

    return full_train_dataset, y_full_train, test_dataset, y_test, label, fam_idx

def main(batch_size, hidden, num_layers, flag, step_size, m, epochs, clf_model, tune, lr, ds_path, trained_model, plot_mtx, mapping, reversed_mapping):
    id = 1

    #Dataset Loading    
    families = ['benjamin', 'berbew', 'ceeinject', 'dinwod', 'ganelp', 'gepys', 'mira', 'sfone', 'sillyp2p', 'small', 'upatre', 'wabot', 'wacatac'] # merge1 - family classification

    # families = ["cleanware", "malware"] # detect

    full_train_dataset, y_full_train, test_dataset, y_test, label, fam_idx = init_all_datasets(ds_path, families, mapping, reversed_mapping)

    num_classes = len(families)

    if not tune:
        if not trained_model:
            #Model
            if clf_model == "gine":
                model = GINE(hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "ginjk":
                model = GINJK(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "ginmlp":
                model = GINMLP(hidden, num_classes, num_layers).to(DEVICE)
            else:
                print("Invalid GNN model")
                return
            # Train model
            start_train = time.time()
            model = train(model, full_train_dataset, batch_size, DEVICE, epochs, step_size, m, flag, lr, eval_mode=False)
            end_train = time.time()
            cprint(f"Training time: {end_train - start_train}", 3)

            save_model(model, f"./saved_models/{clf_model}_model.pkl")
        else:
            model = load_model(f"./saved_models/{clf_model}_model.pkl")
        
        # Test model
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
        start_test = time.time()
        accuracy, loss, y_pred = test(model, test_loader, batch_size, DEVICE)
        end_test = time.time()
        cprint(f"Testing time: {end_test - start_test}", 3)
        cprint(f"GNN: Evaluation accuracy & loss, {accuracy:%}, {loss}",id)
        # Compute metrics
        acc, prec, rec, f1, bal_acc = compute_metrics(y_test, y_pred)
        cprint("--------------------------------------------------",id)
        cprint(f"GNN: Test accuracy: {acc}",id)
        cprint(f"GNN: Test balanced accuracy: {bal_acc}",id)
        cprint(f"GNN: Test f1: {f1}",id)
        cprint(f"GNN: Test precision: {prec}",id)
        cprint(f"GNN: Test recall: {rec}",id)
        cprint("--------------------------------------------------",id)

        if plot_mtx:
            # Plot confusion matrix
            plot_confusion_matrix(y_test, y_pred, fam_idx, model_name=clf_model)

    else:
        if clf_model == 'gine':
            cprint("Tuning parameters for gine",id)
            results = tune_parameters_gine(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs)
            write_stats_to_csv(results, clf_model)
        elif clf_model == 'ginjk':
            cprint("Tuning parameters for ginjk",id)
            results = tune_parameters_ginjk(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs)
            write_stats_to_csv(results, clf_model)
        elif clf_model == 'ginmlp':
            cprint("Tuning parameters for ginmlp",id)
            results = tune_parameters_ginmlp(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs)
            write_stats_to_csv(results, clf_model)
        else:
            print("Not implemented yet")

if __name__ == "__main__":
    print("Hello World")

    # Parse arguments:
    parser = argparse.ArgumentParser()
    parser.add_argument('--hidden', type=int, default=64, help='Number of hidden units.')
    parser.add_argument('--batch_size', type=int, default=8, help='Batch size for training.')
    parser.add_argument('--num_layers', type=int, default=0, help='Number of GNN layers.')
    parser.add_argument('--flag', action="store_true", help='Whether to use FLAG.')
    parser.add_argument('--step_size', type=float, default=8e-3 , help='Step size for FLAG.')
    parser.add_argument('--m', type=int, default=3, help='Ascent steps for FLAG.')
    parser.add_argument('--lr', type=float, default=0.001, help='Learning rate.')
    parser.add_argument('--epochs', type=int, default=200, help='Number of training epochs per iteration.')
    parser.add_argument('--clf_model', type=str, default='gine', help='Which GNN to use.')
    parser.add_argument('--tune', action="store_true", help='Whether to tune parameters.')
    parser.add_argument('--trained_model', action="store_true", help='Already trained model, whether we train or not')
    parser.add_argument('--plot_mtx', action='store_true', help="Whether to plot confusion matrix after classification")
    parser.add_argument('--ds_path', type=str, default=None, help="Path to dataset (folders with .gs files)")

    args = parser.parse_args()
    print(args)

    # Init variables according to arguments
    hidden = args.hidden
    batch_size = args.batch_size
    num_layers = args.num_layers
    flag = args.flag
    step_size = args.step_size
    m = args.m
    lr = args.lr
    epochs = args.epochs
    clf_model = args.clf_model
    tune = args.tune
    trained_model = args.trained_model
    plot_mtx = args.plot_mtx
    ds_path = args.ds_path

    if not ds_path:
        ds_path = "./datasets/classification" # classification task
        # ds_path = "./datasets/detection" # detection task

    with open("./gnn_helpers/mappings.json") as f:
        reversed_mapping = json.load(f)
    mapping = {v: k for k, v in reversed_mapping.items()}

    main(batch_size, hidden, num_layers, flag, step_size, m, epochs, clf_model, tune, lr, ds_path, trained_model, plot_mtx, mapping, reversed_mapping)
    