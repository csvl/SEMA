import time

from . import dataset_utils
import torch
import numpy as np
import flwr as fl
from .utils import save_model, cprint

from ..models.GINEClassifier import GINE
from ..models.GINJKClassifier import GINJK
from ..models.GINMLPClassifier import GINMLP

from .metrics_utils import *
from .models_training import *

from torch_geometric.loader import DataLoader

DEVICE: str = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
print(f"Using device: {DEVICE}")

BATCH_SIZE_TEST=32

fam_idx = {}

def tune_parameters_ginjk(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs):
    hidden = [128, 64, 32]
    num_layers = [4, 5, 6, 7]
    lr = [0.001]
    batch_sizes = [64, 32, 16, 8]
    flag = False
    fg = flag
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    
    best_bal_acc = 0

    folds = 4
    train_indexes, val_indexes = dataset_utils.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = dataset_utils.get_folds(full_train_dataset,train_indexes, val_indexes)

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
                        model = train(model, train_data, bs, DEVICE, epochs, flag=fg, lr=r, val_dataset=val_data, y_val=y_val_data)
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
                        acc, prec, rec, f1, bal_acc = compute_metrics(y_val_data, y_pred)
                        cv_curr_params["acc"].append(acc)
                        cv_curr_params["prec"].append(prec)
                        cv_curr_params["rec"].append(rec)
                        cv_curr_params["f1"].append(f1)
                        cv_curr_params["bal_acc"].append(bal_acc)
                        cprint("--------------------------------------------------",1)
                        cprint(f"GNN: Test accuracy: {acc}",1)
                        cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                        cprint(f"GNN: Test f1: {f1}",1)
                        cprint(f"GNN: Test precision: {prec}",1)
                        cprint(f"GNN: Test recall: {rec}",1)
                        cprint("--------------------------------------------------",1)
                        
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
    model = train(model, full_train_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./saved_models/ginjk_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = compute_metrics(y_test, y_pred)
    cprint("--------------------------------------------------",0)
    cprint(f"GNN: Test accuracy: {final_acc}",0)
    cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    cprint(f"GNN: Test f1: {final_f1}",0)
    cprint(f"GNN: Test precision: {final_prec}",0)
    cprint(f"GNN: Test recall: {final_rec}",0)
    cprint("--------------------------------------------------",0)
    plot_confusion_matrix(y_test, y_pred, fam_idx, model_name="ginjk")
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

def tune_parameters_gine(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs):
    hidden = [128, 64, 32]
    num_layers = [4, 5, 6, 7]
    lr = [0.001]
    batch_sizes = [64, 32, 16, 8]
    flag = False
    fg = flag
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    best_bal_acc = 0

    folds = 4
    train_indexes, val_indexes = dataset_utils.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = dataset_utils.get_folds(full_train_dataset,train_indexes, val_indexes)

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
                        model = GINE(h, num_classes, l).to(DEVICE)
                        start = time.time()
                        model = train(model, train_data, bs, DEVICE, epochs, flag=fg, lr=r, val_dataset=val_data, y_val=y_val_data)
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
                        acc, prec, rec, f1, bal_acc = compute_metrics(y_val_data, y_pred)
                        cv_curr_params["acc"].append(acc)
                        cv_curr_params["prec"].append(prec)
                        cv_curr_params["rec"].append(rec)
                        cv_curr_params["f1"].append(f1)
                        cv_curr_params["bal_acc"].append(bal_acc)
                        cprint("--------------------------------------------------",1)
                        cprint(f"GNN: Test accuracy: {acc}",1)
                        cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                        cprint(f"GNN: Test f1: {f1}",1)
                        cprint(f"GNN: Test precision: {prec}",1)
                        cprint(f"GNN: Test recall: {rec}",1)
                        cprint("--------------------------------------------------",1)
                        
                        to_write = {"hidden": h, "layers": l, "lr": r, "batch_size": bs, "flag": fg, "step_size": -1, "m": -1, "acc": acc, "prec": prec, "rec": rec, "f1": f1, "bal_acc": bal_acc, "training_time": trn_time, "testing_time": tst_time, "loss": loss}
                        write_cross_val_stats_to_tmp_csv(to_write, "gine", fold)

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
                    write_stats_to_tmp_csv(current_params, "gine")
    # return best_params
    # Evaluate best model
    model = GINE(best_params["hidden"], num_classes, best_params["layers"]).to(DEVICE)
    # tain and get training time:
    start = time.time()
    model = train(model, full_train_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./saved_models/gine_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = compute_metrics(y_test, y_pred)
    cprint("--------------------------------------------------",0)
    cprint(f"GNN: Test accuracy: {final_acc}",0)
    cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    cprint(f"GNN: Test f1: {final_f1}",0)
    cprint(f"GNN: Test precision: {final_prec}",0)
    cprint(f"GNN: Test recall: {final_rec}",0)
    cprint("--------------------------------------------------",0)
    plot_confusion_matrix(y_test, y_pred, fam_idx, model_name="gine")
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

def tune_parameters_ginmlp(full_train_dataset, y_full_train, test_dataset, y_test, num_classes, fam_idx, epochs):
    hidden = [128, 64, 32]
    num_layers = [4, 5, 6, 7]
    lr = [0.001]
    batch_sizes = [64, 32, 16, 8]
    flag = False
    fg = flag
    best_params = {}
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    best_bal_acc = 0
    best_loss = float('inf')
    best_fscore = 0

    folds = 4
    train_indexes, val_indexes = dataset_utils.cross_val_split_dataset_indexes(full_train_dataset, y_full_train, folds)
    train_folds, y_train_folds, val_folds, y_val_folds = dataset_utils.get_folds(full_train_dataset,train_indexes, val_indexes)

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
                        model = GINMLP(h, num_classes, l).to(DEVICE)
                        start = time.time()
                        model = train(model, train_data, bs, DEVICE, epochs, flag=fg, lr=r, val_dataset=val_data, y_val=y_val_data)
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
                        acc, prec, rec, f1, bal_acc = compute_metrics(y_val_data, y_pred)
                        cv_curr_params["acc"].append(acc)
                        cv_curr_params["prec"].append(prec)
                        cv_curr_params["rec"].append(rec)
                        cv_curr_params["f1"].append(f1)
                        cv_curr_params["bal_acc"].append(bal_acc)
                        cprint("--------------------------------------------------",1)
                        cprint(f"GNN: Test accuracy: {acc}",1)
                        cprint(f"GNN: Test balanced accuracy: {bal_acc}",1)
                        cprint(f"GNN: Test f1: {f1}",1)
                        cprint(f"GNN: Test precision: {prec}",1)
                        cprint(f"GNN: Test recall: {rec}",1)
                        cprint("--------------------------------------------------",1)
                        
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
    model = GINMLP(best_params["hidden"], num_classes, best_params["layers"]).to(DEVICE)
    # tain and get training time:
    start = time.time()
    model = train(model, full_train_dataset, best_params["batch_size"], DEVICE, epochs, best_params["step_size"], best_params["m"], best_params["flag"], best_params["lr"], eval_mode=False)
    end = time.time()
    save_model(model, f"./saved_models/rgin_model.pkl") 
    start_test = time.time()
    accuracy, loss, y_pred = test(model, test_loader, best_params["batch_size"], DEVICE)
    end_test = time.time()
    final_acc, final_prec, final_rec, final_f1, final_bal_acc = compute_metrics(y_test, y_pred)
    cprint("--------------------------------------------------",0)
    cprint(f"GNN: Test accuracy: {final_acc}",0)
    cprint(f"GNN: Test balanced accuracy: {final_bal_acc}",0)
    cprint(f"GNN: Test f1: {final_f1}",0)
    cprint(f"GNN: Test precision: {final_prec}",0)
    cprint(f"GNN: Test recall: {final_rec}",0)
    cprint("--------------------------------------------------",0)
    plot_confusion_matrix(y_test, y_pred, fam_idx, model_name="rgin")
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

