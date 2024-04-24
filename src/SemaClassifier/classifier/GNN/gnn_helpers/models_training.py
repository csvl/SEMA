import time

from matplotlib import pyplot as plt
# from gnn_helpers.dataset_utils as dataset_utils
import argparse
import os
import torch
import numpy as np
import flwr as fl
from .utils import read_mapping, read_mapping_inverse, save_model, load_model, cprint
import copy
import json

from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score , f1_score, balanced_accuracy_score

from torch_geometric.loader import DataLoader

import pandas as pd
import seaborn as sns

from .metrics_utils import *

DEVICE: str = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")

BATCH_SIZE_TEST=32

fam_idx = {}

def one_epoch_train_vanilla(model, train_loader, device, optimizer, criterion, val_loader=None, y_val=None, eval_mode=True):
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

def one_epoch_train_flag(model, train_loader, device, optimizer, criterion, step_size, m, val_loader=None, y_val=None, eval_mode=True): 
    '''
    @misc{https://doi.org/10.48550/arxiv.2010.09891,
        doi = {10.48550/ARXIV.2010.09891},
        url = {https://arxiv.org/abs/2010.09891},
        author = {Kong, Kezhi and Li, Guohao and Ding, Mucong and Wu, Zuxuan and Zhu, Chen and Ghanem, Bernard and Taylor, Gavin and Goldstein, Tom},
        keywords = {Machine Learning (cs.LG), Machine Learning (stat.ML), FOS: Computer and information sciences, FOS: Computer and information sciences},
        title = {Robust Optimization as Data Augmentation for Large-scale Graphs},
        publisher = {arXiv},
        year = {2020},
        copyright = {arXiv.org perpetual, non-exclusive license}
        }
    '''
    model.train()
    train_loss = 0
    train_correct = 0
    train_total = 0
    for data in train_loader:
        data = data.to(device)
        optimizer.zero_grad()
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
    if eval_mode:
        val_acc, val_loss, y_pred = test(model, val_loader, BATCH_SIZE_TEST, device)
        val_bal_acc = 0
        if y_val:
            val_bal_acc = balanced_accuracy_score(y_val, y_pred)
        return model, train_acc, train_loss, val_acc, val_loss, val_bal_acc
    else:
        return model, train_acc, train_loss, 0,0,0

def train(model, train_dataset, batch_size, device, epochs, step_size=8e-3, m=3, flag=False, lr=0.001, val_dataset=None, y_val=None, eval_mode=True):
    print(f"Are you training with flag ? : {flag}, step_size: {step_size}, m: {m}, lr: {lr}")
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,
                            T_max = 42, # Maximum number of iterations.
                            eta_min = 1e-4) # Minimum learning rate.
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)
    count = 0
    best_model_wts = copy.deepcopy(model.state_dict())
    alpha = 0.5
    beta = 0.5
    best_combined_metric = float('inf')
    val_bal_acc = 0
    for epoch in range(epochs):
        if flag:
            model, train_acc, train_loss, val_acc, val_loss, val_bal_acc = one_epoch_train_flag(model, train_loader, device, optimizer, criterion, step_size, m, val_loader=val_loader, y_val=y_val, eval_mode=eval_mode)
        else:
            model, train_acc, train_loss, val_acc, val_loss, val_bal_acc = one_epoch_train_vanilla(model, train_loader, device, optimizer, criterion, val_loader=val_loader, y_val=y_val, eval_mode=eval_mode)
        scheduler.step()
        if eval_mode:
            combined_metric = alpha * val_loss + beta * (1 - val_bal_acc)
            if combined_metric < best_combined_metric:
                best_model_wts = copy.deepcopy(model.state_dict())
                count = 0
                best_combined_metric = combined_metric
            else:
                count += 1
            cprint(f"Epoch {epoch+1}: Lr: {optimizer.param_groups[0]['lr']:.5} | Train acc: {train_acc:.4%} | Train loss: {train_loss:.4} | Val accuracy: {val_acc:.4%} | Val bal accuracy: {val_bal_acc:.4%} | Val loss: {val_loss:.4} | metric: {combined_metric:.4} | count: {count}", 1)
            if count > 20:
                print(f"Early stop at epoch {epoch} because our metric did not improve for {count} epochs.")
                break
        else:
            cprint(f"Epoch {epoch+1}: Train acc: {train_acc:.4%} | Train loss: {train_loss:.4}", 1)
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
