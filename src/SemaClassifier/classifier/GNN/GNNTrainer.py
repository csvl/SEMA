import torch
import torch.nn.functional as F
import progressbar
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
from torch_geometric.datasets import TUDataset
from torch_geometric import compile
import numpy as np
import logging

from ..Classifier import Classifier
from .GINClassifier import GIN
from .GINJKClassifier import GINJK
from .GCNClassifier import GCN
from .RGINClassifier import RanGIN
from .RGINJKClassifier import RanGINJK
from .GINJKFlagClassifier import GINJKFlag
from .GNNExplainability import GNNExplainability
from .utils import gen_graph_data, read_gs_4_gnn, read_json_4_gnn
import copy

# import torch._dynamo
# torch._dynamo.config.suppress_errors = True

CLASS_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_CLASS = False # TODO

class GNNTrainer(Classifier):
    def __init__(self, path, name, threshold=0.45,
                 families=['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT'],
                 num_layers=4, input_path=None, hidden=32, lr=0.001, epoch=350, batch_size=32, 
                 flag=True, patience=-1, m=3, step_size=8e-3, graph_model="ER", net_linear=False, drop_ratio=0.5,
                 drop_path_p=0.01, edge_p=0.6, net_seed=47,
                 residual=False):
        
        super().__init__(path, name, threshold)

        self.path = path
        self.name = name
        self.families = families
        self.mapping = self.read_mapping('mapping.txt')
        self.mapping_inv = self.read_mapping_inverse('mapping.txt')
        self.dataset = []
        self.label = []
        self.label_dict = {}
        self.fam_idx = []
        self.fam_dict = {}
        self.n_features = 0
        classes = set()
        for fname in glob.glob("{0}/*/*.gs".format(path)):
            dirname,name = self.get_label(fname)
            # self.data.append((fname,dirname))
            classes.add(dirname)
        self.classes = sorted(list(classes))
        self.clf = None
        self.y_pred = list()

        self.num_layers = num_layers
        self.hidden = hidden
        self.lr = lr
        self.epoch = epoch
        self.batch_size = batch_size
        self.input_path = input_path
        self.flag = flag
        self.patience = patience
        if self.patience > 0:
            print("Patience for early stoppping is set to {}".format(self.patience))
        self.m=m
        self.step_size=step_size

        self.train_index, self.val_index = [],[]
        self.original_path = ""
        self.train_dataset, self.val_dataset, self.y_train, self.y_val = [],[],[],[]
        # self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        self.device = torch.device("cpu")

        self.init_dataset(self.input_path)        
        self.log.info("Dataset len: " + str(len(self.dataset)))
        self.dataset_len = len(self.dataset)
        num_classes = len(np.unique(self.label))

        if self.dataset_len > 0:            
            self.split_dataset()
            # dataset = self.train_dataset
            # val_dataset = self.val_dataset
            if self.name=="gin":
                self.clf = GIN(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers)
            # elif self.name=="sage":
            #     self.clf = GraphSAGE(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers)
            elif self.name=="ginjk":
                self.clf = GINJK(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers)
            elif self.name=="rgin":
                self.clf = RanGIN(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers)
            elif self.name=="fginjk":
                self.clf = GINJKFlag(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers,
                                     drop_ratio=drop_ratio, residual=residual)
            elif self.name=="rginjk":
                self.clf = RanGINJK(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers,
                                    graph_model=graph_model, net_linear=net_linear, drop_ratio=drop_ratio,
                                    drop_path_p=drop_path_p, edge_p=edge_p, net_seed=net_seed,
                                    residual=residual)
            elif self.name=="gcn":
                self.clf = GCN(self.train_dataset[0].num_node_features, self.hidden, num_classes, self.num_layers)
            
            # self.clf = compile(self.clf, fullgraph=True) # dynamic=True


    def init_dataset(self, path):
        if path[-1] != "/":
            path += "/"
        self.log.info("Path: " + path)
        bar = progressbar.ProgressBar(max_value=len(self.families))
        bar.start()
        self.original_path = path
        self.dataset = []
        self.label = []
        for family in self.families:
            path = self.path.replace("/SemaClassifier","/") + '/'  + self.original_path + family + '/' if self.path.replace("/SemaClassifier","/") not in self.original_path else self.original_path + family + '/'
            path = path.replace("SemaClassifier/","").replace("/src/src/","/src/") # TODO refactor
            # path = path.replace("SemaClassifier/","").replace("/src/","/") # TODO refactor
            # path = path.replace("//","/")
            self.log.info("Subpath: " + path)
            if not os.path.isdir(path) :
                self.log.info("Dataset should be a folder containing malware classify by familly in subfolder")
                exit(-1)
            else:
                #filenames = glob.glob(path+'/SCDG_*') + glob.glob(path+'test/SCDG_*')
                filenames = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
                if len(filenames) > 1 and family not in self.fam_idx :
                    self.fam_idx.append(family)
                    self.fam_dict[family] = len(self.fam_idx) - 1
                for file in filenames:
                    # if file.endswith(".gs"):
                    if file.endswith(".json"):
                        # edges, nodes, vertices, edge_labels = read_gs_4_gnn(file, self.mapping)
                        edges, nodes, vertices, edge_labels = read_json_4_gnn(file, self.mapping_inv)
                        data = gen_graph_data(edges, nodes, vertices, edge_labels, self.fam_dict[family])
                        if len(edges) > 0:
                            if len(nodes) > 1:
                                self.dataset.append(data)
                            if BINARY_CLASS and len(nodes) > 1:
                                if family == 'clean':
                                    self.label.append(family)
                                else:
                                    self.label.append('malware')
                            else:
                                if len(nodes) > 1:
                                    self.label.append(family)
        # import pdb; pdb.set_trace()
        bar.finish()

    def split_dataset(self):
        print("########## Dataset:")
        # import pdb; pdb.set_trace()
        for f in self.dataset[:200:20]:
            print(f"{f.num_nodes} -- {f.num_edges}")
        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.4, random_state=24)
        for train, test in sss.split(self.dataset, self.label):
            self.train_index = train
            self.val_index = test
        for i in self.train_index:
            self.train_dataset.append(self.dataset[i])
            self.y_train.append(self.label[i])  
        for i in self.val_index:
            self.val_dataset.append(self.dataset[i])
            self.y_val.append(self.label[i])
        print("########## Train set:")
        # import pdb; pdb.set_trace()
        for g in self.train_dataset[:4]:
            print(f"{g.num_nodes} -- {g.num_edges}")
        print("########## Valid set:")
        for e in self.val_dataset[:4]:
            print(f"{e.num_nodes} -- {e.num_edges}")

    def get_label(self,fname):
        name = os.path.basename(fname)
        dirname = os.path.basename(os.path.dirname(fname))
        dname = dirname.split("_")[0]
        return dname, name
    
    def train_vanilla(self, path):
        print("############# VANILLA TRAINING #############")
        epoch=self.epoch
        lr=self.lr
        batch_size=self.batch_size

        if self.dataset_len > 0:            
            # self.split_dataset()
            dataset = self.train_dataset
            val_dataset = self.val_dataset
            # dataset = self.dataset
            
            train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

            optimizer = torch.optim.Adam(self.clf.parameters(), lr=lr)#, weight_decay=5e-4)
            criterion = torch.nn.CrossEntropyLoss()
            # scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)
            # scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, 
            #                             T_0 = 8,# Number of iterations for the first restart
            #                             T_mult = 1, # A factor increases TiTi​ after a restart
            #                             eta_min = 1e-5) # Minimum learning rate
            scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,
                              T_max = 42, # Maximum number of iterations.
                             eta_min = 1e-4) # Minimum learning rate.
            # import pdb; pdb.set_trace()
            torch.autograd.set_detect_anomaly(True)
            # patience = 100 # Number of epoch to wait for improvement
            best_val_loss = float('inf')
            best_val_bal_acc = 0
            best_val_f1_score = 0
            best_model_wts = copy.deepcopy(self.clf.state_dict())
            counter = 0  # Counter to keep track of epoch without improvement
            for ep in range(epoch):
                self.clf.train()
                # import pdb; pdb.set_trace()
                loss_all = 0
                for data in train_loader:
                    optimizer.zero_grad()

                    out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch)
                    loss = criterion(out, data.y)
                    # loss = self.clf.loss(out, dataset.data.y, dataset.data.edge_index)
                    loss.backward()
                    loss_all += data.num_graphs * loss.item()
                    optimizer.step()

                before_lr = optimizer.param_groups[0]["lr"]
                scheduler.step()
                after_lr = optimizer.param_groups[0]["lr"]
                train_loss = loss_all / len(dataset)

                # validation
                self.clf.eval()
                val_loss = 0
                val_correct = 0
                val_predictions = []
                targets = []
                with torch.no_grad():
                    for val_data in val_loader:
                        val_out = self.clf(val_data.x, val_data.edge_index, val_data.edge_attr, val_data.batch)
                        val_loss += criterion(val_out, val_data.y).item()
                        val_pred = val_out.argmax(dim=1)
                        val_correct += val_pred.eq(val_data.y).sum().item()
                        val_predictions.extend(val_pred.cpu().numpy())
                        targets.extend(val_data.y)
                
                val_loss /= len(val_dataset)
                val_accuracy = (val_correct / len(val_dataset))*100
                val_bal_accuracy = balanced_accuracy_score(targets, val_predictions)*100
                val_f1_score = f1_score(targets, val_predictions,average='weighted')*100

                # Check if validation loss has improved
                if ((val_f1_score > best_val_f1_score) or
                    (val_f1_score == best_val_f1_score and best_val_bal_acc < val_bal_accuracy) or
                    (val_f1_score == best_val_f1_score and best_val_bal_acc == val_bal_accuracy and val_loss < best_val_loss)):
                    best_val_loss = val_loss
                    best_val_bal_acc = val_bal_accuracy
                    best_val_f1_score = val_f1_score
                    # Save the current best model
                    # torch.save(self.clf.state_dict(), best_model_path)
                    best_model_wts = copy.deepcopy(self.clf.state_dict())
                    counter = 0                   
                else:
                    counter += 1
                    if self.patience > 0 and counter >= self.patience:
                        print("Validation loss did not improve for {} epoch. Stopping training.".format(self.patience))
                        break
                print("Epoch: %03d/%03d: lr %.5f -> %.5f | Train Loss: %.5f | Val Loss: %.5f | Val Accuracy: %.3f%% | Val BAL Accuracy: %.3f%% | Val f1-score: %.3f%% | patience counter: %.0f" % (ep, epoch-1, before_lr, after_lr, train_loss, val_loss, val_accuracy, val_bal_accuracy, val_f1_score, counter))
            self.clf.load_state_dict(best_model_wts)
            self.log.info('--------------------FIT OK----------------')
        else:
            self.log.info("Dataset length should be > 0")
            exit(-1)

    def train_flag(self, path):
        print("############# FLAG TRAINING #############")
        epoch=self.epoch
        lr=self.lr
        batch_size=self.batch_size
        step_size = self.step_size
        m = self.m
        
        # import pdb; pdb.set_trace()
        if self.dataset_len > 0:            
            # self.split_dataset()
            dataset = self.train_dataset
            val_dataset = self.val_dataset
            # dataset = self.dataset

            train_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

            optimizer = torch.optim.Adam(self.clf.parameters(), lr=lr)#, weight_decay=5e-4)
            criterion = torch.nn.CrossEntropyLoss()
            # scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)
            # scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(optimizer, 
            #                             T_0 = 8,# Number of iterations for the first restart
            #                             T_mult = 1, # A factor increases TiTi​ after a restart
            #                             eta_min = 1e-5) # Minimum learning rate
            scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer,
                              T_max = 42, # Maximum number of iterations.
                             eta_min = 1e-4) # Minimum learning rate.
            # import pdb; pdb.set_trace()
            torch.autograd.set_detect_anomaly(True)
            best_val_loss = float('inf')
            best_val_bal_acc = 0
            best_val_f1_score = 0
            best_model_wts = copy.deepcopy(self.clf.state_dict())
            counter = 0  # Counter to keep track of epoch without improvement
            for ep in range(epoch):
                self.clf.train()
                # import pdb; pdb.set_trace()
                loss_all = 0
                for data in train_loader:
                    optimizer.zero_grad()

                    perturb = torch.FloatTensor(data.x.shape[0], self.hidden).uniform_(-step_size, step_size)
                    perturb.requires_grad_()

                    out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch, perturb)
                    loss = criterion(out, data.y)
                    loss /= m
                    # loss = self.clf.loss(out, dataset.data.y, dataset.data.edge_index)

                    for _ in range(m-1):
                        loss.backward()
                        perturb_data = perturb.detach() + step_size * torch.sign(perturb.grad.detach())
                        perturb.data = perturb_data.data
                        perturb.grad[:] = 0

                        out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch, perturb)
                        loss = criterion(out, data.y)
                        loss /= m

                    loss.backward()
                    loss_all += data.num_graphs * loss.item()
                    optimizer.step()
                before_lr = optimizer.param_groups[0]["lr"]
                scheduler.step()
                after_lr = optimizer.param_groups[0]["lr"]
                train_loss = loss_all / len(dataset)

                # validation
                self.clf.eval()
                val_loss = 0
                val_correct = 0
                val_predictions = []
                targets = []
                with torch.no_grad():
                    for val_data in val_loader:
                        val_out = self.clf(val_data.x, val_data.edge_index, val_data.edge_attr, val_data.batch)
                        val_loss += criterion(val_out, val_data.y).item()
                        val_pred = val_out.argmax(dim=1)
                        val_correct += val_pred.eq(val_data.y).sum().item()
                        val_predictions.extend(val_pred.cpu().numpy())
                        targets.extend(val_data.y)
                
                val_loss /= len(val_dataset)
                val_accuracy = (val_correct / len(val_dataset))*100
                val_bal_accuracy = balanced_accuracy_score(targets, val_predictions)*100
                val_f1_score = f1_score(targets, val_predictions,average='weighted')*100

                # Check if validation loss has improved
                if ((val_f1_score > best_val_f1_score) or
                    (val_f1_score == best_val_f1_score and best_val_bal_acc < val_bal_accuracy) or
                    (val_f1_score == best_val_f1_score and best_val_bal_acc == val_bal_accuracy and val_loss < best_val_loss)):
                    best_val_loss = val_loss
                    best_val_bal_acc = val_bal_accuracy
                    best_val_f1_score = val_f1_score
                    # Save the current best model
                    # torch.save(self.clf.state_dict(), best_model_path)
                    best_model_wts = copy.deepcopy(self.clf.state_dict())
                    counter = 0                   
                else:
                    counter += 1
                    if self.patience > 0 and counter >= self.patience:
                        print("Validation loss did not improve for {} epoch. Stopping training.".format(self.patience))
                        break
                print("Epoch: %03d/%03d: lr %.5f -> %.5f | Train Loss: %.5f | Val Loss: %.5f | Val Accuracy: %.3f%% | Val BAL Accuracy: %.3f%% | Val f1-score: %.3f%% | patience counter: %.0f" % (ep, epoch-1, before_lr, after_lr, train_loss, val_loss, val_accuracy, val_bal_accuracy, val_f1_score, counter))
            self.clf.load_state_dict(best_model_wts)
            self.log.info('--------------------FIT OK----------------')
        else:
            self.log.info("Dataset length should be > 0")
            exit(-1)

    def train(self, path):
        if self.flag:
            self.train_flag(path)
        else:
            self.train_vanilla(path)

    @torch.no_grad()
    def classify(self,path=None):
        if path is None:
            self.clf.eval()
            val_loader = DataLoader(self.val_dataset, batch_size=64, shuffle=False)
            self.y_pred = list()
            correct = 0
            for data in val_loader:
                out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch)
                pred = out.argmax(dim=1)
                # correct += int((pred == data.y).sum())
                correct += pred.eq(data.y).sum().item()
                for p in pred:
                    # print(p)
                    self.y_pred.append(self.fam_idx[p])
            # print("AAAAAccuracy: " + str(correct/len(self.dataset)))
        else:
            # import pdb; pdb.set_trace()
            self.init_dataset(path)
            print("Dataset len: " + str(len(self.dataset)))
            import pdb; pdb.set_trace()
            self.clf.eval()
            val_loader = DataLoader(self.dataset, batch_size=64, shuffle=False)
            self.y_pred = list()
            correct = 0
            
            for data in val_loader:
                out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch)
                pred = out.argmax(dim=1)
                # correct += int((pred == data.y).sum())
                correct += pred.eq(data.y).sum().item()
                for p in pred:
                    # print(p)
                    self.y_pred.append(self.fam_idx[p])
            # print("AAAAAccuracy: " + str(correct/len(self.dataset)))
            # import pdb; pdb.set_trace() 


    @torch.no_grad()
    def detection(self,path=None):
        if path is None:
            self.clf.eval()
            val_loader = DataLoader(self.val_dataset, batch_size=64, shuffle=False)
            self.y_pred = list()
            correct = 0
            # import pdb; pdb.set_trace() 
            for data in val_loader:
                out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch)
                pred = out.argmax(dim=1)
                # correct += int((pred == data.y).sum())
                correct += pred.eq(data.y).sum().item()
                for p in pred:
                    # print(p)
                    self.y_pred.append(self.fam_idx[p])
            # print("AAAAAccuracy: " + str(correct/len(self.dataset)))
        else:
            self.init_dataset(path)
            self.clf.eval()
            val_loader = DataLoader(self.dataset, batch_size=64, shuffle=False)
            self.y_pred = list()
            correct = 0
            # import pdb; pdb.set_trace() 
            for data in val_loader:
                out = self.clf(data.x, data.edge_index, data.edge_attr, data.batch)
                pred = out.argmax(dim=1)
                # correct += int((pred == data.y).sum())
                correct += pred.eq(data.y).sum().item()
                for p in pred:
                    # print(p)
                    self.y_pred.append(self.fam_idx[p])
            # print("AAAAAccuracy: " + str(correct/len(self.dataset)))


    def get_stat_classifier(self):
        logging.basicConfig(level=logging.INFO)
        
        accuracy = accuracy_score(self.label, self.y_pred)*100
        balanced_accuracy = balanced_accuracy_score(self.label, self.y_pred)*100
        precision = precision_score(self.label, self.y_pred,average='weighted')*100
        recall = recall_score(self.label, self.y_pred,average='weighted')*100
        f_score = f1_score(self.label, self.y_pred,average='weighted')*100

        self.log.info("Accuracy %2.2f %%" %(accuracy))
        self.log.info("Balanced accuracy %2.2f %%" %(balanced_accuracy))
        self.log.info("Precision %2.2f %%" %(precision))
        self.log.info("Recall %2.2f %%" %(recall))
        self.log.info("F1-score %2.2f %%" %(f_score))

        
        # with open(f"output/gnn_eval/flag_eval_stats.csv", "a") as f:
        #     f.write(f"{accuracy},{balanced_accuracy},{precision},{recall},{f_score},{self.flag}\n")
    
        if BINARY_CLASS:
            conf = confusion_matrix(self.label,self.y_pred,labels=['clean','malware'])
            y_score1 = self.clf.predict_proba(self.K_val)[:,1]
            false_positive_rate1, true_positive_rate1, threshold1 = roc_curve(self.label, y_score1,pos_label='clean')
            plt.subplots(1, figsize=(10,10))
            plt.title('Receiver Operating Characteristic -  DecisionTree')
            plt.plot(false_positive_rate1, true_positive_rate1)
            plt.plot([0, 1], ls="--")
            plt.plot([0, 0], [1, 0] , c=".7"), plt.plot([1, 1] , c=".7")
            plt.ylabel('True Positive Rate')
            plt.xlabel('False Positive Rate')
            plt.show()
            print("OOOOOOHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
            # plt.savefig(self.original_path + "figure_binary.png")

        else:
            conf = confusion_matrix(self.label,self.y_pred,labels=self.fam_idx)

        list_name =[]
        for y in self.label:
            if y not in list_name:
                list_name.append(y)
        figsize = (10,7)
        fontsize=9
        if BINARY_CLASS:
            df_cm = pd.DataFrame(conf, index=['clean','malware'], columns=['clean','malware'],)
        else :
            df_cm = pd.DataFrame(conf, index=self.fam_idx, columns=self.fam_idx,)
        fig = plt.figure(figsize=figsize)
        try:
            heatmap = sns.heatmap(df_cm, annot=True, fmt="d",cbar=False)
        except ValueError:
            raise ValueError("Confusion matrix values must be integers.")
        heatmap.yaxis.set_ticklabels(heatmap.yaxis.get_ticklabels(), rotation=0, ha='right', fontsize=fontsize)
        heatmap.xaxis.set_ticklabels(heatmap.xaxis.get_ticklabels(), rotation=45, ha='right', fontsize=fontsize)
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        plt.show()
        print("AAAAAAHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
        plt.savefig(self.original_path + "figure.png")
        # plt.savefig("/home/sambt/Desktop/figure.png")
        return accuracy, balanced_accuracy, precision, recall, f_score
    
    def explain(self, path=None, output_path=None):
        if path is None:
            dataset = self.val_dataset
            loader = DataLoader(dataset, batch_size=1, shuffle=True)
            GNNExplainability(dataset, loader, self.clf, self.mapping, self.fam_idx, output_path).explain()
        else:
            self.init_dataset(path)
            dataset = self.dataset
            loader = DataLoader(dataset, batch_size=1, shuffle=True)
            GNNExplainability(dataset, loader, self.clf, self.mapping, self.fam_idx, output_path).explain()
