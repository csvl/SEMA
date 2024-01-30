import time

from matplotlib import pyplot as plt
import GNN_script
import argparse
import os
import sys
import torch
import numpy as np
import flwr as fl
from utils import read_mapping, read_mapping_inverse, save_model, load_model
from collections import OrderedDict
from typing import Dict, List, Tuple
import copy
import json

from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score , f1_score, balanced_accuracy_score

from GINJKFlagClassifier import GINJKFlag
from GINClassifier import GIN
from GINJKClassifier import GINJK
from RGINClassifier import R_GINJK
from RGINJKClassifier import RanGINJK
import sys
sys.path.append("./SemaClassifier/classifier/")
from SVM.SVMClassifier import SVMClassifier
from SVM.SVMWLClassifier import SVMWLClassifier

from GNNExplainability import GNNExplainability

from torch_geometric.loader import DataLoader

import pandas as pd
import seaborn as sns


DEVICE: str = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")

BATCH_SIZE_TEST=32

fam_idx = {}

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

def get_datasets_wl(dataset, trn_idx, tst_idx, label):
    train_dataset = []
    test_dataset = []
    y_train = []
    y_test = []
    for i in trn_idx:
        train_dataset.append(dataset[i])
        y_train.append(label[i])
    for i in tst_idx:
        test_dataset.append(dataset[i])
        y_test.append(label[i])
    return train_dataset, y_train, test_dataset, y_test

def one_epoch_train_vanilla(model, train_loader, val_loader, device, optimizer, criterion, y_val=None, eval_mode=True):
    model.train()
    train_loss = 0
    train_correct = 0
    train_total = 0
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()
        output = model(data.x, data.edge_index, data.edge_attr, data.batch)
        loss = criterion(output, data.y)
        loss.backward()
        train_loss += loss.item() * data.num_graphs
        optimizer.step()
        train_total += data.num_graphs
        train_correct += (output.argmax(1) == data.y).sum().item()
    train_loss /= train_total
    train_acc = train_correct / train_total
    if eval_mode:
        val_acc, val_loss, y_pred = test(model, val_loader, BATCH_SIZE_TEST, device)
        val_bal_acc = 0
        if y_val:
            val_bal_acc = balanced_accuracy_score(y_val, y_pred)
        return model, train_acc, train_loss, val_acc, val_loss, val_bal_acc
    else:
        return model, train_acc, train_loss, 0,0,0

def one_epoch_train_flag(model, train_loader, val_loader, device, optimizer, criterion, step_size, m):
    model.train()
    train_loss = 0
    train_correct = 0
    train_total = 0
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()

        # import pdb; pdb.set_trace()

        perturb = torch.FloatTensor(data.x.shape[0], model.hidden).uniform_(-step_size, step_size).to(device)
        perturb.requires_grad_()

        output = model(data.x, data.edge_index, data.edge_attr, data.batch, perturb)
        loss = criterion(output, data.y)
        loss /= m

        for _ in range(m-1):
            loss.backward()
            perturb_data = perturb.detach() + step_size * torch.sign(perturb.grad.detach())
            perturb.data = perturb_data.data
            perturb.grad[:] = 0

            output = model(data.x, data.edge_index, data.edge_attr, data.batch, perturb)
            loss = criterion(output, data.y)
            loss /= m

        loss.backward()
        train_loss += loss.item() * data.num_graphs
        optimizer.step()
        train_total += data.num_graphs
        train_correct += (output.argmax(1) == data.y).sum().item()
    train_loss /= train_total
    train_acc = train_correct / train_total
    val_acc, val_loss, _ = test(model, val_loader, BATCH_SIZE_TEST, device)
    return model, train_acc, train_loss, val_acc, val_loss

def train(model, train_dataset, val_dataset, batch_size, device, epochs, step_size=8e-3, m=3, flag=False, lr=0.001, y_val=None, eval_mode=True):
    print(f"Training with flag: {flag}, step_size: {step_size}, m: {m}, lr: {lr}")
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,
                            T_max = 42, # Maximum number of iterations.
                            eta_min = 1e-4) # Minimum learning rate.
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    best_val_loss = float('inf')
    count = 0
    best_model_wts = copy.deepcopy(model.state_dict())
    alpha = 0.5
    beta = 0.5
    best_combined_metric = float('inf')
    val_bal_acc = 0
    for epoch in range(epochs):
        if flag:
            model, train_acc, train_loss, val_acc, val_loss = one_epoch_train_flag(model, train_loader, val_loader, device, optimizer, criterion, step_size, m)
        else:
            model, train_acc, train_loss, val_acc, val_loss, val_bal_acc = one_epoch_train_vanilla(model, train_loader, val_loader, device, optimizer, criterion, y_val=y_val, eval_mode=eval_mode)
        scheduler.step()
        if eval_mode:
            combined_metric = alpha * val_loss + beta * (1 - val_bal_acc)
            if combined_metric < best_combined_metric:
                best_model_wts = copy.deepcopy(model.state_dict())
                count = 0
                best_combined_metric = combined_metric
            else:
                count += 1
            GNN_script.cprint(f"Epoch {epoch+1}: Lr: {optimizer.param_groups[0]['lr']:.5} | Train acc: {train_acc:.4%} | Train loss: {train_loss:.4} | Val accuracy: {val_acc:.4%} | Val bal accuracy: {val_bal_acc:.4%} | Val loss: {val_loss:.4} | metric: {combined_metric:.4} | count: {count}", 1)
            if count > 20:
                print(f"Early stop at epoch {epoch} because our metric did not improve for {count} epochs.")
                break
        else:
            GNN_script.cprint(f"Epoch {epoch+1}: Train acc: {train_acc:.4%} | Train loss: {train_loss:.4}", 1)
    if eval_mode:
        model.load_state_dict(best_model_wts)
    return model 

def test(model, test_loader, batch_size, device):
    model.eval()
    criterion = torch.nn.CrossEntropyLoss()
    y_pred = []
    test_loss = 0.0
    test_correct = 0
    test_total = 0
    with torch.inference_mode():
        for data in test_loader:
            data = data.to(device)
            output = model(data.x, data.edge_index, data.edge_attr, data.batch)
            loss = criterion(output, data.y).item()
            test_loss += loss * data.num_graphs
            test_total += data.num_graphs
            pred = output.argmax(dim=1)
            test_correct += pred.eq(data.y).sum().item()
            for p in pred:
                y_pred.append(p.item())
    test_loss /= test_total
    test_acc = test_correct / test_total
    return test_acc, test_loss, y_pred

def explain(model, dataset, mapping, fam_idx, output_path):
    loader = DataLoader(dataset, batch_size=1, shuffle=False)
    explainer = GNNExplainability(dataset, loader, model, mapping, fam_idx, output_path)
    explainer.explain()

def computre_metrics(y_true, y_pred, fam_idx):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average='weighted')
    rec = recall_score(y_true, y_pred, average='weighted')
    f1 = f1_score(y_true, y_pred, average='weighted')
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    return acc, prec, rec, f1, bal_acc

def plot_confusion_matrix(y_true, y_pred, fam_idx, model_name):
    # plot confusion matrix
    if type(y_true[0]) != str:  
        y_true_label = [fam_idx[i] for i in y_true]
        y_pred_label = [fam_idx[i] for i in y_pred]
    else:
        y_true_label = y_true
        y_pred_label = y_pred

    # import pdb; pdb.set_trace()
    cm = confusion_matrix(y_true_label, y_pred_label, labels=np.unique(fam_idx))
    print(cm)

    df_cm = pd.DataFrame(cm, index = np.unique(fam_idx),
                    columns = np.unique(fam_idx))
    plt.figure(figsize = (10,7))
    heatmap = sns.heatmap(df_cm, annot=True, cmap="Blues", fmt="d",cbar=False)
    heatmap.yaxis.set_ticklabels(heatmap.yaxis.get_ticklabels(), rotation=0, ha='right', fontsize=14)
    heatmap.xaxis.set_ticklabels(heatmap.xaxis.get_ticklabels(), rotation=45, ha='right', fontsize=14)
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.title(f"Confusion matrix for {model_name}")
    plt.savefig(f"confusion_matrix_{model_name}_1.png")
    plt.show()

def tune_parameters_ginjk(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx):
    hidden = [128, 64, 32]
    num_layers = [4, 5, 6, 7]
    lr = [0.001]
    batch_sizes = [64, 32, 16, 8]
    flag = False
    fg = flag
    step_size = [8e-3, 5e-3, 1e-3]
    m_steps = [3, 5, 7]
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    best_bal_acc = 0
    best_loss = float('inf')
    best_fscore = 0

    folds = 4
    train_indexes, val_indexes = GNN_script.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = get_folds(full_train_dataset,train_indexes, val_indexes)

    for h in hidden:
        for l in num_layers:
            for r in lr:
                for bs in batch_sizes:
                    cv_curr_params = {}
                    cv_curr_params["hidden"] = h
                    cv_curr_params["layers"] = l
                    cv_curr_params["lr"] = r
                    cv_curr_params["batch_size"] = bs
                    cv_curr_params["flag"] = fg
                    cv_curr_params["step_size"] = -1
                    cv_curr_params["m"] = -1
                    cv_curr_params["acc"], cv_curr_params["prec"], cv_curr_params["rec"], cv_curr_params["f1"], cv_curr_params["bal_acc"], cv_curr_params["training_time"], cv_curr_params["testing_time"], cv_curr_params["loss"] = [], [], [], [], [], [], [], []

                    for fold in range(folds):
                        train_data, y_train_data = train_folds[fold], y_train_folds[fold]
                        val_data, y_val_data = val_folds[fold], y_val_folds[fold]
                        
                        print(f"Fold: {fold}, Hidden: {h}, Layers: {l}, LR: {r}, FLAG: {fg}")
                        model = GINJK(train_data[0].num_node_features, h, num_classes, l).to(DEVICE)
                        start = time.time()
                        model = train(model, train_data, val_data, bs, DEVICE, epochs, flag=fg, lr=r, y_val=y_val_data)
                        end = time.time()
                        trn_time = end - start
                        print(f"Training time: {trn_time}")
                        cv_curr_params["training_time"].append(trn_time)
                        val_data_loader = DataLoader(val_data, batch_size=32, shuffle=False)
                        start = time.time()
                        accuracy, loss, y_pred = test(model, val_data_loader, bs, DEVICE)
                        end = time.time()
                        tst_time = end - start
                        print(f"Testing time: {tst_time}")
                        cv_curr_params["testing_time"].append(tst_time)
                        cv_curr_params["loss"].append(loss)
                        acc, prec, rec, f1, bal_acc = computre_metrics(y_val_data, y_pred, fam_idx)
                        cv_curr_params["acc"].append(acc)
                        cv_curr_params["prec"].append(prec)
                        cv_curr_params["rec"].append(rec)
                        cv_curr_params["f1"].append(f1)
                        cv_curr_params["bal_acc"].append(bal_acc)
                        GNN_script.cprint("--------------------------------------------------",1)
                        GNN_script.cprint(f"GNN: Test accuracy: {acc}",1)
                        GNN_script.cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                        GNN_script.cprint(f"GNN: Test precision: {prec}",1)
                        GNN_script.cprint(f"GNN: Test recall: {rec}",1)
                        GNN_script.cprint(f"GNN: Test f1: {f1}",1)
                        GNN_script.cprint("--------------------------------------------------",1)
                        
                        to_write = {"hidden": h, "layers": l, "lr": r, "batch_size": bs, "flag": fg, "step_size": -1, "m": -1, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "bal_acc": bal_acc, "training_time": trn_time, "testing_time": tst_time, "loss": loss}
                        write_cross_val_stats_to_tmp_csv(to_write, "ginjk", fold)

                    current_params = {}
                    current_params["hidden"] = h
                    current_params["layers"] = l
                    current_params["lr"] = r
                    current_params["batch_size"] = bs
                    current_params["flag"] = fg
                    current_params["step_size"] = -1
                    current_params["m"] = -1
                    
                    current_params["training_time"] = np.mean(cv_curr_params["training_time"])
                    current_params["testing_time"] = np.mean(cv_curr_params["testing_time"])
                    current_params["loss"] = np.mean(cv_curr_params["loss"])
                    current_params["acc"] = np.mean(cv_curr_params["acc"])
                    current_params["prec"] = np.mean(cv_curr_params["prec"])
                    current_params["rec"] = np.mean(cv_curr_params["rec"])
                    current_params["f1"] = np.mean(cv_curr_params["f1"])
                    current_params["bal_acc"] = np.mean(cv_curr_params["bal_acc"])

                    if current_params["bal_acc"] > best_bal_acc:
                        best_bal_acc = current_params["bal_acc"]
                        best_loss = loss
                        best_fscore = current_params["f1"]
                        best_params["hidden"] = h
                        best_params["layers"] = l
                        best_params["lr"] = r
                        best_params["batch_size"] = bs
                        best_params["acc"] = current_params["acc"]
                        best_params["prec"] = current_params["prec"]
                        best_params["rec"] = current_params["rec"]
                        best_params["f1"] = current_params["f1"]
                        best_params["bal_acc"] = current_params["bal_acc"]
                        best_params["loss"] = loss
                        best_params["flag"] = fg
                        best_params["step_size"] = -1
                        best_params["m"] = -1
                    print("Current:")
                    print(current_params)
                    print("Best:")
                    print(best_params)
                    write_stats_to_tmp_csv(current_params, "ginjk")
    # return best_params
    # Evaluate best model
    model = GINJK(full_train_dataset[0].num_node_features, best_params["hidden"], num_classes, best_params["layers"]).to(DEVICE)
    # tain and get training time:
    start = time.time()
    model = train(model, full_train_dataset, test_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = computre_metrics(y_test, y_pred, fam_idx)
    GNN_script.cprint("--------------------------------------------------",0)
    GNN_script.cprint(f"GNN: Test accuracy: {final_acc}",0)
    GNN_script.cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    GNN_script.cprint(f"GNN: Test precision: {final_prec}",0)
    GNN_script.cprint(f"GNN: Test recall: {final_rec}",0)
    GNN_script.cprint(f"GNN: Test f1: {final_f1}",0)
    GNN_script.cprint("--------------------------------------------------",0)
    results = {}
    results["final_acc"] = final_acc
    results["final_prec"] = final_prec
    results["final_rec"] = final_rec
    results["final_f1"] = final_f1
    results["final_bal_acc"] = final_bal_acc
    results["final_loss"] = loss
    results["best_params"] = best_params
    results["training_time"] = end - start
    results["testing_time"] = end_test - start_test
    return results

def tune_parameters_fginjk(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx):
    hidden = [128, 64, 32]
    num_layers = [4, 5, 6, 7]
    lr = [0.001]
    batch_sizes = [64, 32, 16, 8]
    flag = False
    fg = flag
    step_size = [8e-3, 5e-3, 1e-3]
    m_steps = [3, 5, 7]
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    best_bal_acc = 0
    best_loss = float('inf')
    best_fscore = 0

    folds = 4
    train_indexes, val_indexes = GNN_script.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = get_folds(full_train_dataset,train_indexes, val_indexes)

    for h in hidden:
        for l in num_layers:
            for r in lr:
                for bs in batch_sizes:
                    if fg:
                        for m in m_steps:
                            for step in step_size:
                                current_params = {}
                                current_params["hidden"] = h
                                current_params["layers"] = l
                                current_params["lr"] = r
                                current_params["batch_size"] = bs
                                current_params["flag"] = fg
                                current_params["step_size"] = step
                                current_params["m"] = m
                                print(f"Hidden: {h}, Layers: {l}, LR: {r}, FLAG: {fg}, M: {m}, Step: {step}")
                                model = GINJKFlag(h, num_classes, l).to(DEVICE)
                                start = time.time()
                                model = train(model, train_dataset, val_dataset, bs, DEVICE, epochs,  step_size=step, m=m, flag=fg, lr=r)
                                end = time.time()
                                trn_time = end - start
                                print(f"Training time: {trn_time}")
                                current_params["training_time"] = trn_time
                                start = time.time()
                                accuracy, loss, y_pred = test(model, val_loader, bs, DEVICE)
                                end = time.time()
                                print(f"Testing time: {end - start}")
                                current_params["loss"] = loss
                                current_params["acc"], current_params["prec"], current_params["rec"], current_params["f1"], current_params["bal_acc"] = computre_metrics(y_val, y_pred, fam_idx)
                                if current_params["bal_acc"] > best_bal_acc:
                                    best_bal_acc = current_params["bal_acc"]
                                    best_loss = loss
                                    best_fscore = current_params["f1"]
                                    best_params["hidden"] = h
                                    best_params["layers"] = l
                                    best_params["lr"] = r
                                    best_params["batch_size"] = bs
                                    best_params["acc"] = current_params["acc"]
                                    best_params["prec"] = current_params["prec"]
                                    best_params["rec"] = current_params["rec"]
                                    best_params["f1"] = current_params["f1"]
                                    best_params["bal_acc"] = current_params["bal_acc"]
                                    best_params["loss"] = loss
                                    best_params["flag"] = fg
                                    best_params["step_size"] = current_params["step_size"]
                                    best_params["m"] = current_params["m"]
                                print("Current:")
                                print(current_params)
                                print("Best:")
                                print(best_params)
                                write_stats_to_tmp_csv(current_params, "fginjk")
                    else:
                        cv_curr_params = {}
                        cv_curr_params["hidden"] = h
                        cv_curr_params["layers"] = l
                        cv_curr_params["lr"] = r
                        cv_curr_params["batch_size"] = bs
                        cv_curr_params["flag"] = fg
                        cv_curr_params["step_size"] = -1
                        cv_curr_params["m"] = -1
                        cv_curr_params["acc"], cv_curr_params["prec"], cv_curr_params["rec"], cv_curr_params["f1"], cv_curr_params["bal_acc"], cv_curr_params["training_time"], cv_curr_params["testing_time"], cv_curr_params["loss"] = [], [], [], [], [], [], [], []

                        for fold in range(folds):
                            train_data, y_train_data = train_folds[fold], y_train_folds[fold]
                            val_data, y_val_data = val_folds[fold], y_val_folds[fold]
                            
                            print(f"Fold: {fold}, Hidden: {h}, Layers: {l}, LR: {r}, FLAG: {fg}")
                            model = GINJKFlag(h, num_classes, l).to(DEVICE)
                            start = time.time()
                            model = train(model, train_data, val_data, bs, DEVICE, epochs, flag=fg, lr=r, y_val=y_val_data)
                            end = time.time()
                            trn_time = end - start
                            print(f"Training time: {trn_time}")
                            cv_curr_params["training_time"].append(trn_time)
                            val_data_loader = DataLoader(val_data, batch_size=32, shuffle=False)
                            start = time.time()
                            accuracy, loss, y_pred = test(model, val_data_loader, bs, DEVICE)
                            end = time.time()
                            tst_time = end - start
                            print(f"Testing time: {tst_time}")
                            cv_curr_params["testing_time"].append(tst_time)
                            cv_curr_params["loss"].append(loss)
                            acc, prec, rec, f1, bal_acc = computre_metrics(y_val_data, y_pred, fam_idx)
                            cv_curr_params["acc"].append(acc)
                            cv_curr_params["prec"].append(prec)
                            cv_curr_params["rec"].append(rec)
                            cv_curr_params["f1"].append(f1)
                            cv_curr_params["bal_acc"].append(bal_acc)
                            GNN_script.cprint("--------------------------------------------------",1)
                            GNN_script.cprint(f"GNN: Test accuracy: {acc}",1)
                            GNN_script.cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                            GNN_script.cprint(f"GNN: Test precision: {prec}",1)
                            GNN_script.cprint(f"GNN: Test recall: {rec}",1)
                            GNN_script.cprint(f"GNN: Test f1: {f1}",1)
                            GNN_script.cprint("--------------------------------------------------",1)
                            
                            to_write = {"hidden": h, "layers": l, "lr": r, "batch_size": bs, "flag": fg, "step_size": -1, "m": -1, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "bal_acc": bal_acc, "training_time": trn_time, "testing_time": tst_time, "loss": loss}
                            write_cross_val_stats_to_tmp_csv(to_write, "fginjk", fold)

                        current_params = {}
                        current_params["hidden"] = h
                        current_params["layers"] = l
                        current_params["lr"] = r
                        current_params["batch_size"] = bs
                        current_params["flag"] = fg
                        current_params["step_size"] = -1
                        current_params["m"] = -1
                        
                        current_params["training_time"] = np.mean(cv_curr_params["training_time"])
                        current_params["testing_time"] = np.mean(cv_curr_params["testing_time"])
                        current_params["loss"] = np.mean(cv_curr_params["loss"])
                        current_params["acc"] = np.mean(cv_curr_params["acc"])
                        current_params["prec"] = np.mean(cv_curr_params["prec"])
                        current_params["rec"] = np.mean(cv_curr_params["rec"])
                        current_params["f1"] = np.mean(cv_curr_params["f1"])
                        current_params["bal_acc"] = np.mean(cv_curr_params["bal_acc"])

                        if current_params["bal_acc"] > best_bal_acc:
                            best_bal_acc = current_params["bal_acc"]
                            best_loss = loss
                            best_fscore = current_params["f1"]
                            best_params["hidden"] = h
                            best_params["layers"] = l
                            best_params["lr"] = r
                            best_params["batch_size"] = bs
                            best_params["acc"] = current_params["acc"]
                            best_params["prec"] = current_params["prec"]
                            best_params["rec"] = current_params["rec"]
                            best_params["f1"] = current_params["f1"]
                            best_params["bal_acc"] = current_params["bal_acc"]
                            best_params["loss"] = loss
                            best_params["flag"] = fg
                            best_params["step_size"] = -1
                            best_params["m"] = -1
                        print("Current:")
                        print(current_params)
                        print("Best:")
                        print(best_params)
                        write_stats_to_tmp_csv(current_params, "fginjk")
    # return best_params
    # Evaluate best model
    model = GINJKFlag(best_params["hidden"], num_classes, best_params["layers"]).to(DEVICE)
    # tain and get training time:
    start = time.time()
    model = train(model, full_train_dataset, test_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = computre_metrics(y_test, y_pred, fam_idx)
    GNN_script.cprint("--------------------------------------------------",0)
    GNN_script.cprint(f"GNN: Test accuracy: {final_acc}",0)
    GNN_script.cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    GNN_script.cprint(f"GNN: Test precision: {final_prec}",0)
    GNN_script.cprint(f"GNN: Test recall: {final_rec}",0)
    GNN_script.cprint(f"GNN: Test f1: {final_f1}",0)
    GNN_script.cprint("--------------------------------------------------",0)
    results = {}
    results["final_acc"] = final_acc
    results["final_prec"] = final_prec
    results["final_rec"] = final_rec
    results["final_f1"] = final_f1
    results["final_bal_acc"] = final_bal_acc
    results["final_loss"] = loss
    results["best_params"] = best_params
    results["training_time"] = end - start
    results["testing_time"] = end_test - start_test
    return results

def tune_parameters_rgin(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx):
    hidden = [64]
    num_layers = [5, 6]
    lr = [0.001]
    batch_sizes = [128, 64, 32, 16, 8]
    flag = False
    fg = flag
    step_size = [8e-3, 5e-3, 1e-3]
    m_steps = [3, 5, 7]
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    best_bal_acc = 0
    best_loss = float('inf')
    best_fscore = 0

    folds = 4
    train_indexes, val_indexes = GNN_script.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = get_folds(full_train_dataset,train_indexes, val_indexes)

    for h in hidden:
        for l in num_layers:
            for r in lr:
                for bs in batch_sizes:
                    if fg:
                        for m in m_steps:
                            for step in step_size:
                                current_params = {}
                                current_params["hidden"] = h
                                current_params["layers"] = l
                                current_params["lr"] = r
                                current_params["batch_size"] = bs
                                current_params["flag"] = fg
                                current_params["step_size"] = step
                                current_params["m"] = m
                                print(f"Hidden: {h}, Layers: {l}, LR: {r}, FLAG: {fg}, M: {m}, Step: {step}")
                                model = R_GINJK(train_dataset[0].num_node_features, h, num_classes, l, drop_ratio=drop_ratio, residual=residual).to(DEVICE)
                                start = time.time()
                                model = train(model, train_dataset, val_dataset, bs, DEVICE, epochs,  step_size=step, m=m, flag=fg, lr=r)
                                end = time.time()
                                trn_time = end - start
                                print(f"Training time: {trn_time}")
                                current_params["training_time"] = trn_time
                                start = time.time()
                                accuracy, loss, y_pred = test(model, val_loader, bs, DEVICE)
                                end = time.time()
                                print(f"Testing time: {end - start}")
                                current_params["loss"] = loss
                                current_params["acc"], current_params["prec"], current_params["rec"], current_params["f1"], current_params["bal_acc"] = computre_metrics(y_val, y_pred, fam_idx)
                                if current_params["bal_acc"] > best_bal_acc:
                                    best_bal_acc = current_params["bal_acc"]
                                    best_loss = loss
                                    best_fscore = current_params["f1"]
                                    best_params["hidden"] = h
                                    best_params["layers"] = l
                                    best_params["lr"] = r
                                    best_params["batch_size"] = bs
                                    best_params["acc"] = current_params["acc"]
                                    best_params["prec"] = current_params["prec"]
                                    best_params["rec"] = current_params["rec"]
                                    best_params["f1"] = current_params["f1"]
                                    best_params["bal_acc"] = current_params["bal_acc"]
                                    best_params["loss"] = loss
                                    best_params["flag"] = fg
                                    best_params["step_size"] = current_params["step_size"]
                                    best_params["m"] = current_params["m"]
                                print("Current:")
                                print(current_params)
                                print("Best:")
                                print(best_params)
                                write_stats_to_tmp_csv(current_params, "rgin")
                    else:
                        cv_curr_params = {}
                        cv_curr_params["hidden"] = h
                        cv_curr_params["layers"] = l
                        cv_curr_params["lr"] = r
                        cv_curr_params["batch_size"] = bs
                        cv_curr_params["flag"] = fg
                        cv_curr_params["step_size"] = -1
                        cv_curr_params["m"] = -1
                        cv_curr_params["acc"], cv_curr_params["prec"], cv_curr_params["rec"], cv_curr_params["f1"], cv_curr_params["bal_acc"], cv_curr_params["training_time"], cv_curr_params["testing_time"], cv_curr_params["loss"] = [], [], [], [], [], [], [], []

                        for fold in range(folds):
                            train_data, y_train_data = train_folds[fold], y_train_folds[fold]
                            val_data, y_val_data = val_folds[fold], y_val_folds[fold]
                            
                            print(f"Fold: {fold}, Hidden: {h}, Layers: {l}, LR: {r}, FLAG: {fg}")
                            model = R_GINJK(h, num_classes, l).to(DEVICE)
                            start = time.time()
                            model = train(model, train_data, val_data, bs, DEVICE, epochs, flag=fg, lr=r, y_val=y_val_data)
                            end = time.time()
                            trn_time = end - start
                            print(f"Training time: {trn_time}")
                            cv_curr_params["training_time"].append(trn_time)
                            val_data_loader = DataLoader(val_data, batch_size=32, shuffle=False)
                            start = time.time()
                            accuracy, loss, y_pred = test(model, val_data_loader, bs, DEVICE)
                            end = time.time()
                            tst_time = end - start
                            print(f"Testing time: {tst_time}")
                            cv_curr_params["testing_time"].append(tst_time)
                            cv_curr_params["loss"].append(loss)
                            acc, prec, rec, f1, bal_acc = computre_metrics(y_val_data, y_pred, fam_idx)
                            cv_curr_params["acc"].append(acc)
                            cv_curr_params["prec"].append(prec)
                            cv_curr_params["rec"].append(rec)
                            cv_curr_params["f1"].append(f1)
                            cv_curr_params["bal_acc"].append(bal_acc)
                            GNN_script.cprint("--------------------------------------------------",1)
                            GNN_script.cprint(f"GNN: Test accuracy: {acc}",1)
                            GNN_script.cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                            GNN_script.cprint(f"GNN: Test precision: {prec}",1)
                            GNN_script.cprint(f"GNN: Test recall: {rec}",1)
                            GNN_script.cprint(f"GNN: Test f1: {f1}",1)
                            GNN_script.cprint("--------------------------------------------------",1)
                            
                            to_write = {"hidden": h, "layers": l, "lr": r, "batch_size": bs, "flag": fg, "step_size": -1, "m": -1, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "bal_acc": bal_acc, "training_time": trn_time, "testing_time": tst_time, "loss": loss}
                            write_cross_val_stats_to_tmp_csv(to_write, "rgin", fold)

                        current_params = {}
                        current_params["hidden"] = h
                        current_params["layers"] = l
                        current_params["lr"] = r
                        current_params["batch_size"] = bs
                        current_params["flag"] = fg
                        current_params["step_size"] = -1
                        current_params["m"] = -1
                        
                        current_params["training_time"] = np.mean(cv_curr_params["training_time"])
                        current_params["testing_time"] = np.mean(cv_curr_params["testing_time"])
                        current_params["loss"] = np.mean(cv_curr_params["loss"])
                        current_params["acc"] = np.mean(cv_curr_params["acc"])
                        current_params["prec"] = np.mean(cv_curr_params["prec"])
                        current_params["rec"] = np.mean(cv_curr_params["rec"])
                        current_params["f1"] = np.mean(cv_curr_params["f1"])
                        current_params["bal_acc"] = np.mean(cv_curr_params["bal_acc"])

                        if current_params["bal_acc"] > best_bal_acc:
                            best_bal_acc = current_params["bal_acc"]
                            best_loss = loss
                            best_fscore = current_params["f1"]
                            best_params["hidden"] = h
                            best_params["layers"] = l
                            best_params["lr"] = r
                            best_params["batch_size"] = bs
                            best_params["acc"] = current_params["acc"]
                            best_params["prec"] = current_params["prec"]
                            best_params["rec"] = current_params["rec"]
                            best_params["f1"] = current_params["f1"]
                            best_params["bal_acc"] = current_params["bal_acc"]
                            best_params["loss"] = loss
                            best_params["flag"] = fg
                            best_params["step_size"] = -1
                            best_params["m"] = -1
                        print("Current:")
                        print(current_params)
                        print("Best:")
                        print(best_params)
                        write_stats_to_tmp_csv(current_params, "rgin")
    # return best_params
    # Evaluate best model
    model = R_GINJK(best_params["hidden"], num_classes, best_params["layers"]).to(DEVICE)
    # tain and get training time:
    start = time.time()
    model = train(model, full_train_dataset, test_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = computre_metrics(y_test, y_pred, fam_idx)
    GNN_script.cprint("--------------------------------------------------",0)
    GNN_script.cprint(f"GNN: Test accuracy: {final_acc}",0)
    GNN_script.cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    GNN_script.cprint(f"GNN: Test precision: {final_prec}",0)
    GNN_script.cprint(f"GNN: Test recall: {final_rec}",0)
    GNN_script.cprint(f"GNN: Test f1: {final_f1}",0)
    GNN_script.cprint("--------------------------------------------------",0)
    results = {}
    results["final_acc"] = final_acc
    results["final_prec"] = final_prec
    results["final_rec"] = final_rec
    results["final_f1"] = final_f1
    results["final_bal_acc"] = final_bal_acc
    results["final_loss"] = loss
    results["best_params"] = best_params
    results["training_time"] = end - start
    results["testing_time"] = end_test - start_test
    return results


def write_stats_to_csv(results, clf_model):
    # Write stats and params in csv file
    if not os.path.isfile(f"stats_cv_{clf_model}.csv"):
        with open(f"stats_cv_{clf_model}.csv", "w") as f:
            f.write("model,acc,prec,rec,f1,bal_acc,loss,hidden,layers,lr,batch_size,flag,step_size,m,train_time,test_time\n")
    
    with open(f"stats_cv_{clf_model}.csv", "a") as f:
        f.write(f"{clf_model},{results['final_acc']},{results['final_prec']},{results['final_rec']},{results['final_f1']},{results['final_bal_acc']},{results['final_loss']},{results['best_params']['hidden']},{results['best_params']['layers']},{results['best_params']['lr']},{results['best_params']['batch_size']},{results['best_params']['flag']},{results['best_params']['step_size']},{results['best_params']['m']},{results['training_time']},{results['testing_time']}\n")

def write_stats_to_tmp_csv(results, clf_model):
    # Write stats and params in csv file
    if not os.path.isfile(f"tmp_avg_stats_cv_{clf_model}.csv"):
        with open(f"tmp_avg_stats_cv_{clf_model}.csv", "w") as f:
            f.write("model,acc,prec,rec,f1,bal_acc,loss,hidden,layers,lr,batch_size,flag,step_size,m,train_time,test_time\n")
    
    with open(f"tmp_avg_stats_cv_{clf_model}.csv", "a") as f:
        f.write(f"{clf_model},{results['acc']},{results['prec']},{results['rec']},{results['f1']},{results['bal_acc']},{results['loss']},{results['hidden']},{results['layers']},{results['lr']},{results['batch_size']},{results['flag']},{results['step_size']},{results['m']},{results['training_time']},{results['testing_time']}\n")

def write_cross_val_stats_to_tmp_csv(results, clf_model, fold):
    # Write stats and params in csv file
    if not os.path.isfile(f"tmp_folds_stats_cv_{clf_model}.csv"):
        with open(f"tmp_folds_stats_cv_{clf_model}.csv", "w") as f:
            f.write("model,acc,prec,rec,f1,bal_acc,loss,hidden,layers,lr,batch_size,fold,flag,step_size,m,train_time,test_time\n")
    
    with open(f"tmp_folds_stats_cv_{clf_model}.csv", "a") as f:
        f.write(f"{clf_model},{results['acc']},{results['prec']},{results['rec']},{results['f1']},{results['bal_acc']},{results['loss']},{results['hidden']},{results['layers']},{results['lr']},{results['batch_size']},fold_{fold},{results['flag']},{results['step_size']},{results['m']},{results['training_time']},{results['testing_time']}\n")


def compare_models():
    pass

def init_all_datasets(path, families, mapping, reversed_mapping):

    id = 1

    # PyG dataset
    dataset, label, fam_idx, fam_dict, dataset_wl = GNN_script.init_dataset(path, families, reversed_mapping, [], {}, False)
    train_idx, test_idx = GNN_script.split_dataset_indexes(dataset, label)

    full_train_dataset,y_full_train, test_dataset, y_test = get_datasets(dataset, train_idx, test_idx)

    # dataset_dict, dataset, label, fam_idx, fam_dict, dataset_wl, dataset_dict_wl = GNN_script.temporal_init_dataset(path, families, reversed_mapping, [], {}, False)
    # full_train_dataset,y_full_train, test_dataset, y_test = GNN_script.temporal_split_train_test(dataset_dict, 0.6)

    GNN_script.cprint(f"GNN {id} : datasets length, {len(dataset)}, {len(full_train_dataset)}, {len(test_dataset)}",id)

    # Validation dataset
    trn_idx, val_idx = GNN_script.split_dataset_indexes(full_train_dataset, y_full_train)
    train_dataset, y_train, val_dataset, y_val = get_datasets(full_train_dataset, trn_idx, val_idx)

    # WL dataset
    wl_full_train_dataset,wl_y_full_train, wl_test_dataset,wl_y_test = get_datasets_wl(dataset_wl, train_idx, test_idx, label)

    # wl_full_train_dataset,wl_y_full_train, wl_test_dataset,wl_y_test = GNN_script.temporal_split_train_test_wl(dataset_dict_wl, 0.6, label)
    GNN_script.cprint(f"WL {id} : datasets length, {len(dataset_wl)}, {len(wl_full_train_dataset)} {len(wl_test_dataset)}",id)

    # import pdb; pdb.set_trace()

    return full_train_dataset, y_full_train, test_dataset, y_test, train_dataset, y_train, val_dataset, y_val, wl_full_train_dataset, wl_y_full_train, wl_test_dataset, wl_y_test, label, fam_idx

def main(batch_size, hidden, num_layers, drop_ratio, residual, rand_graph, flag, step_size, m, epochs, net_linear, drop_path_p, edge_p, clf_model, tune, lr, ds_path, explaining, trained_model, plot_mtx, mapping, reversed_mapping):
    id = 1
    #Dataset Loading
    # families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
    
    families = ['benjamin', 'berbew', 'ceeinject', 'dinwod', 'ganelp', 'gepys', 'mira', 'sfone', 'sillyp2p', 'small', 'upatre', 'wabot', 'wacatac'] # merge1

    # families = ['berbew', 'ceeinject', 'dinwod', 'ganelp', 'sfone', 'sillyp2p', 'small', 'upatre', 'wabot'] # merge0

    # families = ['berbew', 'ceeinject', 'dinwod', 'ganelp', 'sfone', 'sillyp2p', 'small', 'upatre', 'wabot', 'wacatac'] # merge2

    # families = ['delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','sytro','wabot','RemcosRAT'] # gs sema

    # families = ['delf','FeakerStealer','ircbot','lamer','nitol','RedLineStealer','sillyp2p','sytro','wabot','RemcosRAT']
    # families = ['delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','sytro','wabot','RemcosRAT','bancteian', 'Sodinokibi']
    # families = ["cleanware", "malware"]

    # families = ['delf','FeakerStealer','gandcrab','lamer','nitol','RedLineStealer','sfone','sillyp2p','sytro','wabot','RemcosRAT', 'Sodinokibi']

    # families = ["FeakerStealer", "RedLineStealer", "RemcosRAT", "Sodinokibi", "delf", "gandcrab", "ircbot", "lamer", "nitol", "sfone", "sillyp2p", "sytro", "wabot"]

    

    full_train_dataset, y_full_train, test_dataset, y_test, train_dataset, y_train, val_dataset, y_val, wl_full_train_dataset, wl_y_full_train, wl_test_dataset, wl_y_test, label, fam_idx = init_all_datasets(ds_path, families, mapping, reversed_mapping)

    num_classes = len(families)

    if not tune:
        if not trained_model:
            #Model
            if clf_model == "fginjk":
                model = GINJKFlag(hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "ginjk":
                model = GINJK(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "gin":
                model = GIN(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "rdginjk":
                model = RanGINJK(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers,
                graph_model=rand_graph, drop_ratio=drop_ratio, residual=residual, net_linear=net_linear, drop_path_p=drop_path_p, edge_p=edge_p).to(DEVICE)
            elif clf_model == "rgin":
                model = R_GINJK(hidden, num_classes, num_layers).to(DEVICE)
            elif clf_model == "wl":
                model = SVMWLClassifier("./databases/examples_samy/BODMAS/01", 0.45, families)
                start_train = time.time()
                model.train(dataset=wl_full_train_dataset, label=wl_y_full_train)
                end_train = time.time()
                GNN_script.cprint(f"Training time: {end_train - start_train}", 3)

                start_test = time.time()
                wl_y_pred = model.classify(dataset=wl_test_dataset)
                end_test = time.time()
                GNN_script.cprint(f"Testing time: {end_test - start_test}", 3)

                wl_acc, wl_prec, wl_rec, wl_f1, wl_bal_acc = computre_metrics(wl_y_test, wl_y_pred, label)
                print()
                GNN_script.cprint("--------------------------------------------------",id)
                GNN_script.cprint(f"WL kernel Test accuracy: {wl_acc}",id)
                GNN_script.cprint(f"WL kernel Test balanced accuracy: {wl_bal_acc}",id)
                GNN_script.cprint(f"WL kernel Test precision: {wl_prec}",id)
                GNN_script.cprint(f"WL kernel Test recall: {wl_rec}",id)
                GNN_script.cprint(f"WL kernel Test f1: {wl_f1}",id)
                print()
                GNN_script.cprint("--------------------------------------------------",id)
                plot_confusion_matrix(wl_y_test, wl_y_pred, fam_idx, model_name="WL")
                save_model(model, f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl") 
                return
            else:
                print("Invalid GNN model")
                return
            # Train model
            start_train = time.time()
            model = train(model, full_train_dataset, val_dataset, batch_size, DEVICE, epochs, step_size, m, flag, lr, eval_mode=False)
            # model = train(model, train_dataset, val_dataset, batch_size, DEVICE, epochs, step_size, m, flag, lr, y_val=y_val)
            end_train = time.time()
            GNN_script.cprint(f"Training time: {end_train - start_train}", 3)

            save_model(model, f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl") 
        else:
            model = load_model(f"./SemaClassifier/classifier/saved_model/{clf_model}_model.pkl")
        
        # Test model
        test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
        start_test = time.time()
        accuracy, loss, y_pred = test(model, test_loader, batch_size, DEVICE)
        end_test = time.time()
        GNN_script.cprint(f"Testing time: {end_test - start_test}", 3)
        GNN_script.cprint(f"GNN: Evaluation accuracy & loss, {accuracy:%}, {loss}",id)
        # Compute metrics
        acc, prec, rec, f1, bal_acc = computre_metrics(y_test, y_pred, fam_idx)
        GNN_script.cprint("--------------------------------------------------",id)
        GNN_script.cprint(f"GNN: Test accuracy: {acc}",id)
        GNN_script.cprint(f"GNN: Test balanced accuracy: {bal_acc}",id)
        GNN_script.cprint(f"GNN: Test precision: {prec}",id)
        GNN_script.cprint(f"GNN: Test recall: {rec}",id)
        GNN_script.cprint(f"GNN: Test f1: {f1}",id)
        GNN_script.cprint("--------------------------------------------------",id)
        
        if plot_mtx:
            # Plot confusion matrix
            plot_confusion_matrix(y_test, y_pred, fam_idx, model_name=clf_model)

        if explaining:
            explain(model, test_dataset[:10], mapping, fam_idx, f"./SemaClassifier/classifier/explain_output/{clf_model}_2/")
        
    else:
        if clf_model == 'fginjk':
            GNN_script.cprint("Tuning parameters for fginjk",id)
            results = tune_parameters_fginjk(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx)
            write_stats_to_csv(results, clf_model)
        elif clf_model == 'ginjk':
            GNN_script.cprint("Tuning parameters for ginjk",id)
            results = tune_parameters_ginjk(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx)
            write_stats_to_csv(results, clf_model)
        elif clf_model == 'rgin':
            GNN_script.cprint("Tuning parameters for rgin",id)
            results = tune_parameters_rgin(full_train_dataset, y_full_train, train_dataset, val_dataset, y_val, test_dataset, y_test, num_classes, fam_idx)
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
    parser.add_argument('--drop_ratio', type=float, default=0.5, help='Dropout ratio (1 - keep probability).')
    parser.add_argument('--residual', type=bool, default=False, help='Whether to add residual connections.')
    parser.add_argument('--rand_graph', type=str, default='NA', help='Random graph model for randomly wired GNN.')
    parser.add_argument('--flag', action="store_true", help='Whether to use FLAG.')
    parser.add_argument('--step_size', type=float, default=8e-3 , help='Step size for FLAG.')
    parser.add_argument('--m', type=int, default=3, help='Ascent steps for FLAG.')
    parser.add_argument('--lr', type=float, default=0.001, help='Learning rate.')
    parser.add_argument('--epochs', type=int, default=200, help='Number of training epochs per iteration.')
    parser.add_argument('--net_linear', action="store_true", default=False, help='Whether to use linear layer.')
    parser.add_argument('--drop_path_p', type=float, default=0.01, help='Drop path probability.')
    parser.add_argument('--edge_p', type=float, default=0.6, help='Edge density in random graph.')
    parser.add_argument('--clf_model', type=str, default='fginjk', help='Which GNN to use.')
    parser.add_argument('--tune', action="store_true", help='Whether to tune parameters.')
    parser.add_argument('--explain', action="store_true", help='Explainability module.')
    parser.add_argument('--trained_model', action="store_true", help='Already trained model, whether we train or not')
    parser.add_argument('--plot_mtx', action='store_true', help="Whether to plot confusion matrix after classification")

    args = parser.parse_args()
    print(args)

    # Init variables according to arguments
    hidden = args.hidden
    batch_size = args.batch_size
    num_layers = args.num_layers
    drop_ratio = args.drop_ratio
    residual = args.residual
    rand_graph = args.rand_graph
    flag = args.flag
    step_size = args.step_size
    m = args.m
    lr = args.lr
    epochs = args.epochs
    net_linear = args.net_linear
    drop_path_p = args.drop_path_p
    edge_p = args.edge_p
    clf_model = args.clf_model
    tune = args.tune
    explaining = args.explain
    trained_model = args.trained_model
    plot_mtx = args.plot_mtx

    # ds_path = "./databases/examples_samy/BODMAS/01"
    # ds_path = "./databases/examples_samy/gs"
    # ds_path = "./databases/examples_samy/out_serena/12/gs"
    # ds_path = "./databases/examples_samy/BODMAS/wselect3_01"
    # ds_path = "./databases/examples_samy/BODMAS/detection/cdfs_01"
    # ds_path = "./databases/examples_samy/big_dataset/merged/alldata/CDFS_b"
    # ds_path = "./databases/examples_samy/big_dataset/merged/alldata/WSELECTSET2_b"
    # ds_path = "./databases/examples_samy/ch_gk/105_cdfs"
    # ds_path = "./databases/examples_samy/ch_gk/three_edges_105_cdfs"
    # ds_path = "./databases/examples_samy/ch_gk/106_wselect3"
    # ds_path = "/root/gs1_sema/gs1"
    ds_path = "/root/gs1_bodmas/gs1"
    # ds_path = "/root/gs1_bodmas/gs0"
    # ds_path = "/root/gs1_bodmas/gs2"
    # ds_path = "/root/gs"

    mapping = read_mapping("./mapping.txt")
    reversed_mapping = read_mapping_inverse("./mapping.txt")

    # with open("mapping_pandi.json") as f:
    #     reversed_mapping = json.load(f)
    # mapping = {v: k for k, v in reversed_mapping.items()}

    main(batch_size, hidden, num_layers, drop_ratio, residual, rand_graph, flag, step_size, m, epochs, net_linear, drop_path_p, edge_p, clf_model, tune, lr, ds_path, explaining, trained_model, plot_mtx, mapping, reversed_mapping)
    