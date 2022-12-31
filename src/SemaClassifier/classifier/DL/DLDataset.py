try:
    import torch
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except:
    print("Deep learning model do no support pypy3")
    exit(-1)
import logging
import progressbar
from gensim.test.utils import datapath
from gensim.models.fasttext import FastText
import numpy as np
import glob


import json
import os 

dir_path = os.path.dirname(os.path.realpath(__file__))

try:
    from clogging.CustomFormatter import CustomFormatter
except:
    from ...clogging.CustomFormatter import CustomFormatter
       

class DLDataset(torch.utils.data.Dataset):
    def __init__(self, rootpath:str, mappath:str, apipath:str,vector_size:int):
        super().__init__()

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("DLDataset")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False

        self.rootdir = rootpath
        self.data = list()
        self.vector_size = vector_size
        self.model = self.api2vector(apipath,vector_size)
        self._apimap = self.read_map(mappath)
        classes = set()
        for fname in glob.glob("{0}/*/*.gs".format(rootpath)):
            dirname,name = self.get_label(fname)
            self.data.append((fname,dirname))
            classes.add(dirname)
            
        self._classes = sorted(list(classes))
        self.load_data()
        
    def load_data(self):
        self.log.info(f"Loading data from {self.rootdir}")
        bar = progressbar.ProgressBar(max_value=len(self.data))
        bar.start()
        data = list()
        self.seq_data= list()
        for index in range(len(self.data)):
            fname, label = self.data[index]
            seq = self.gs2seqvector(fname,self._apimap, self.model.wv)
            if seq is None: continue
            data.append((fname, label))
            seq = torch.from_numpy(seq).float()
            self.seq_data.append(seq.to(device))
            bar.update(index+1)
        bar.finish()    
        self.data= data
        self.y = np.zeros((len(self.data), len(self._classes)))
        for index in range(len(self.data)):
            fname, label = self.data[index]
            if label in self._classes:
                l = self._classes.index(label)
                self.y[index][l] = 1.0
        self.y = torch.from_numpy(self.y).float().to(device)
    
    def __getitem__(self, index:int):
        if index < len(self.data) and index >=0:
            return self.seq_data[index].view(1,-1, self.vector_size*2), self.y[index].view(1,-1),self.data[index]
        
    def __len__(self):
        return len(self.data)
    
    def read_map(self,fname):
        f =open(fname)
        apimap = list()
        for line in f:
            line = line.strip()
            api = line.split(" ")[-1]
            apimap.append(api)
        f.close()
        return apimap

    def get_label(self,fname):
        name = os.path.basename(fname)
        dirname = os.path.basename(os.path.dirname(fname))
        dname = dirname.split("_")[0]
        return dname, name
        
    def init_vector_model(self,vector_size =10, apiname = "APInameseq.txt",mappath = "mapping.txt"):
        model = self.api2vector(apiname,vector_size) # os.path.join(dir_path, apiname)
        apimap = self.read_map(mappath) #os.path.join(dir_path, mappath)
        return model, apimap

    def api2vector(self,apiname,vector_size=10, reset=0):
        save_model = os.path.join(dir_path, "wordmodel")
        if os.path.exists(save_model) and reset ==0:
            model = FastText.load(save_model)
            return model
        corpus_file = datapath(apiname)
        self.log.info(corpus_file)
        self.log.info(apiname)
        model = FastText(vector_size=vector_size, epochs=100)
        model.build_vocab(corpus_file=apiname) # corpus_file
        model.train(corpus_file=apiname, epochs=model.epochs, total_examples=model.corpus_count, total_words= model.corpus_total_words)
        model.save(save_model)
        return model

    def traces2vector(self,fname, wv):
        with open(fname) as f:
            data = json.load(f)
        traces = list()
        for i in data:
            if i == "sections": continue
            t =" "
            for j in data[i]["trace"]:
                t+=j["name"]+" "
            traces.append(t)
        v = wv[traces[0]]
        for i in range(1,len(traces)):
            v+=wv[traces[i]]
        v = v/len(traces)
        return v
        
    def gs2seqvector(self,fname,apimap,wv):
        G= self.read_gs(fname)
        seq = None
        for V,E in G:
            for v1,v2 in E:
                #self.log.info(v1,v2,apimap[v1], apimap[v2])
                #v = [v1,v2]#
                v= wv[[apimap[v1],apimap[v2]]].reshape(1,-1) #wv[f"{apimap[v1]} {apimap[v2]}"]##
                if seq is None:
                    seq = v
                else:
                    seq = np.append(seq,v, axis=0)
            if seq is None:
                for v1 in V:
                    v = wv[[apimap[v1],apimap[v1]]].reshape(1,-1)
                    if seq is not None:
                        seq = np.append(seq,v, axis=0)
                        #seq = np.append(seq,[v1,v1], axis=0)
                    else:
                        seq = v
                        #seq = np.array([v1,v1])
        return seq

    def read_gs(self,fname):
        f = open(fname)
        G = list()
        V = list()
        E = list()
        for line in f:
            s = line.strip()
            sp = s.split(" ")
            if sp[0] == 't':
                if len(E) >0 or len(V)>0:
                    G.append((V,E))
                V = list()
                E = list()
            elif sp[0] == 'v':
                V.append(eval(sp[2]))
            elif sp[0] == 'e':
                E.append((eval(sp[1]), eval(sp[2])))
        if len(E) >0 or len(V)>0:
            G.append((V,E))
        f.close()
        return G
        
    def encode_gs(self,E,V):
        code = list()
        for v1,v2 in E:
            c = "{0:09b}{0:09b}".format(V[v1],V[v2])
            x = np.array(list(c))
            code.append((x=='1').astype(float))
        return np.array(code)
        
    @property
    def classes(self):
        return self._classes

    @classes.setter
    def classes(self, value):
        self._classes = value

    """
    def __getitem__(self, index:int):
        if index < len(self.data) and index >=0:
            fname, label = self.data[index]
            seq = gs2seqvector(fname,self._apimap, self.model.wv)
            idx = self.classes.index(label)
            y = self.target_transform(idx)
            return seq.reshape(1,-1, self.vector_size), y.reshape(1,-1)
    """
        
