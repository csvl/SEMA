import glob
import logging
import os
import pickle
import re
import subprocess
import numpy as np
import progressbar
import pandas as pd
from sklearn.model_selection import train_test_split,StratifiedShuffleSplit
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score , f1_score
from grakel import Graph
from grakel.datasets import fetch_dataset
from grakel.kernels import WeisfeilerLehman, VertexHistogram,ShortestPath,RandomWalk,RandomWalkLabeled,PropagationAttr,NeighborhoodSubgraphPairwiseDistance,WeisfeilerLehmanOptimalAssignment,PyramidMatch
from sklearn.svm import SVC
from sklearn.metrics import roc_curve, roc_auc_score

try:
    from ..Classifier import Classifier
    from clogging.CustomFormatter import CustomFormatter
except:
    from ..Classifier import Classifier
    from ...clogging.CustomFormatter import CustomFormatter
     

CLASS_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_CLASS = False # TODO


class SVMClassifier(Classifier):
    def __init__(self,path,name, threshold=0.45, 
                 families=['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']):
        super().__init__(path,name, threshold)
        f = open(CLASS_DIR+'/dico/myDico5.pkl','rb')
        self.dico_precomputed = pickle.load(f)
        f.close()
        self.path = path  
        self.mapping = self.read_mapping('mapping.txt')
        self.mapping_inv = self.read_mapping_inverse('mapping.txt')
        self.dataset = []
        self.label = []
        self.fam_idx = []
        self.families = families
        self.clf = None
        self.y_pred = None

        self.K_val = None
        self.K_train = None
        self.train_index, self.val_index = [],[]
        self.original_path = ""
        self.train_dataset, self.val_dataset, self.y_train, self.y_val = [],[],[],[]

    def init_dataset(self, path):
        if path[-1] != "/":
            path += "/"
        self.log.info("Path: " + path)
        bar = progressbar.ProgressBar(max_value=len(self.families))
        bar.start()
        self.original_path = path
        for family in self.families:
            path = self.path + '/'  + self.original_path + family + '/'
            path = path.replace("ToolChainClassifier/","") # todo
            self.log.info("Subpath: " + path)
            if not os.path.isdir(path) :
                self.log.info("Dataset should be a folder containing malware classify by familly in subfolder")
                exit(-1)
            else:
                #filenames = glob.glob(path+'/SCDG_*') + glob.glob(path+'test/SCDG_*')
                filenames = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
                if len(filenames) > 1 :
                    self.fam_idx.append(family)
                for file in filenames:
                    if file.endswith(".gs"):
                        G = self.read_gs(file,self.mapping)
                        if len(G.node_labels) > 1:
                            self.dataset.append(G)
                        if BINARY_CLASS and len(G.node_labels) > 1:
                            if family == 'clean':
                                self.label.append(family)
                            else:
                                self.label.append('malware')
                        else:
                            if len(G.node_labels) > 1:
                                self.label.append(family)
        bar.finish()
    
    def split_dataset(self):
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

    def get_stat_classifier(self):
        self.log.info("Accuracy %2.2f %%" %(accuracy_score(self.y_val, self.y_pred)*100))
        self.log.info("Precision %2.2f %%" %(precision_score(self.y_val, self.y_pred,average='weighted')*100))
        self.log.info("Recall %2.2f %%" %(recall_score(self.y_val, self.y_pred,average='weighted')*100))
        f_score = f1_score(self.y_val, self.y_pred,average='weighted')*100
        self.log.info("F1-score %2.2f %%" %(f_score))
    
        if BINARY_CLASS:
            conf = confusion_matrix(self.y_val,self.y_pred,labels=['clean','malware'])
            y_score1 = self.clf.predict_proba(self.K_val)[:,1]
            false_positive_rate1, true_positive_rate1, threshold1 = roc_curve(self.y_val, y_score1,pos_label='clean')
            plt.subplots(1, figsize=(10,10))
            plt.title('Receiver Operating Characteristic - DecisionTree')
            plt.plot(false_positive_rate1, true_positive_rate1)
            plt.plot([0, 1], ls="--")
            plt.plot([0, 0], [1, 0] , c=".7"), plt.plot([1, 1] , c=".7")
            plt.ylabel('True Positive Rate')
            plt.xlabel('False Positive Rate')
            plt.show()
            plt.savefig(self.original_path + "figure_binary.png")

        else:
            conf = confusion_matrix(self.y_val,self.y_pred,labels=self.fam_idx)

        list_name =[]
        for y in self.y_val:
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
        plt.savefig(self.original_path + "figure.png")
        return f_score
    