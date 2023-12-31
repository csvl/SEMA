import glob
import logging
import os
import pickle
from matplotlib import pyplot as plt
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
    # from clogging.CustomFormatter import CustomFormatter
except:
    from .SVMClassifier import SVMClassifier
    # from ...clogging.CustomFormatter import CustomFormatter


CLASS_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_CLASS = False # TODO


class SVMWLClassifier(SVMClassifier):
    def __init__(self,path,threshold=0.45, 
                 families=['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']):
        
        super().__init__(path,'WL', threshold, families)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        # ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("SVMWLClassifier")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False
        self.gk = None

    def classify(self,path=None, dataset=None):
        if dataset is not None:
            self.dataset = dataset
            self.K_test = self.gk.transform(self.dataset)
            self.y_pred = self.clf.predict(self.K_test)
        elif path is None:
            self.y_pred = self.clf.predict(self.K_val)
        else:
            super().init_dataset(path)
            print("Dataset len: " + str(len(self.dataset)))
            K_test = self.gk.transform(self.dataset)
            self.y_pred = self.clf.predict(K_test)
        return self.y_pred


    def detection(self,path=None, dataset=None):
        if dataset is not None:
            self.dataset = dataset
            self.K_test = self.gk.transform(self.dataset)
            self.y_pred = self.clf.predict(self.K_test)
        elif path is None:
            self.y_pred = self.clf.predict(self.K_val)
        else:
            super().init_dataset(path)
            K_test = self.gk.transform(self.dataset)
            self.y_pred = self.clf.predict(K_test)


    def train(self,path=None, dataset=None, label=None):
        if dataset is not None:
            self.dataset = dataset
        elif path is not None:
            super().init_dataset(path)
        else:
            self.log.info("Dataset length should be > 0")
            exit(-1)
        # import pdb; pdb.set_trace()
        self.log.info("Dataset len: " + str(len(self.dataset)))
        self.dataset_len = len(self.dataset)

        if self.dataset_len > 0:
            super().split_dataset(label)
            self.gk = WeisfeilerLehmanOptimalAssignment(normalize=True)
            self.K_train = self.gk.fit_transform(self.train_dataset)
            self.K_val = self.gk.transform(self.val_dataset)
            f = open(CLASS_DIR+'/dico/myDico6.pkl','wb')
            pickle.dump(self.dico_precomputed,f)
            f.close()
            self.clf = SVC(kernel='precomputed',probability=True,random_state=42)
            self.clf.fit(self.K_train, self.y_train)
            self.log.info('--------------------FIT OK----------------')
        else:
            self.log.info("Dataset length should be > 0")
            exit(-1)
    
    
