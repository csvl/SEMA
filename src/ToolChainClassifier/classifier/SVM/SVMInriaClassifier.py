import glob
import logging
import os
import pickle
import subprocess
import numpy as np

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
    from .SVMClassifier import SVMClassifier
    from clogging.CustomFormatter import CustomFormatter
except:
    from .SVMClassifier import SVMClassifier
    from ...clogging.CustomFormatter import CustomFormatter
        
CLASS_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_CLASS = False # TODO

class SVMInriaClassifier(SVMClassifier):    
    def __init__(self,path,threshold=0.45, 
                 families=['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']):
        
        super().__init__(path,'Inria', threshold,families)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("SVMInriaClassifier")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False
    
    def classify(self,path=None):
        if path is None:
            self.y_pred = self.clf.predict(self.K_val)
        else:
            super().init_dataset(path)
            K_test = self.manual_kernel_gram_matrix(self.dataset,self.train_dataset)
            self.y_pred = self.clf.predict(K_test)
            print("Prediction:")
            print(self.y_pred)

    def detection(self,path=None):
        pass

    def train(self,path):
        super().init_dataset(path)
        
        self.log.info("Dataset len: " + str(len(self.dataset)))
        self.dataset_len = len(self.dataset)
        if len(self.dataset) > 0:
            super().split_dataset()
            self.log.info('-----------------------------------------')
            self.K_train = self.manual_kernel_gram_matrix(self.train_dataset,self.train_dataset)
            self.log.info('-----------------TRAIN OK-------------------')
            self.K_val = self.manual_kernel_gram_matrix(self.val_dataset,self.train_dataset)
            self.log.info('------------------TEST OK---------------')
            f = open(CLASS_DIR+'/dico/myDico6.pkl','wb')
            pickle.dump(self.dico_precomputed,f)
            f.close()
            self.clf = SVC(kernel='precomputed',probability=True)
            self.clf.fit(self.K_train, self.y_train)
            self.log.info('--------------------FIT OK----------------')
        else:
            self.log.info("Dataset length should be > 0")
            exit(-1)
    
