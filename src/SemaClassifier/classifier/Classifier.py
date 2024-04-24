import glob
import logging
import os
import subprocess
from matplotlib import pyplot as plt
import numpy as np
from grakel import Graph
from grakel.datasets import fetch_dataset

# try:
#     from clogging.CustomFormatter import CustomFormatter
# except:
#     from ..clogging.CustomFormatter import CustomFormatter
        
class Classifier():
    def __init__(self,path, name, threshold):
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        # ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("Classifier")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False
        
        self.name = name
        self.threshold = threshold
        self.gspan_path = "" #path.replace("SemaClassifier","submodules/SEMA-quickspan/build/") 
        self.dico_precomputed = []
        self.dataset_len = 0

        self.train_dataset = None
        self.val_dataset = None
        self.test_dataset = None
        self.stat_dataset = None

        self.fscore = None
        self.accuracy = None
        self.precision = None
        self.recall = None
        
        self.loss = None
        self.tpr = None
        self.balanced_accuracy = None

        
    # Classify malware use the model
    # in : path = list of samples to classify
    # TODO: not good way to write that ch
    # TODO 
    # if path = none -> load model and test the path
    # else: apply on test test from training set
    # same for detection
    def classify(self,path=None):
        """
        Sort by familly
        """
        pass

    def detection(self,path=None):
        """
        Malware vs cleanware
        """
        pass

    # Train the model
    def train(self,path):
        pass

    def read_mapping(self,path):
        map_file = open(path,'r')
        mapping = {}
        for line in map_file:
            tab = line.split('\n')[0].split(' ')
            mapping[int(tab[0])] = tab[1]
        map_file.close()
        return mapping


    def manual_kernel(self,g1, g2):
        return self.merge_in_gs(g1,g2,'test.gs')
        
    def manual_kernel_gram_matrix(self,G1, G2):
        gram_matrix = np.zeros((len(G1), len(G2)))
        for i, g1 in enumerate(G1):
            for j, g2 in enumerate(G2):
                gram_matrix[i, j] = self.manual_kernel(g1, g2)
                #self.log.info(gram_matrix[i, j])
        return gram_matrix

    def read_mapping_inverse(self,path):
        map_file = open(path,'r')
        mapping = {}
        for line in map_file:
            tab = line.split('\n')[0].split(' ')
            mapping[tab[1]] = int(tab[0])
        map_file.close()
        return mapping

    
    def read_gs(self,path,mapping,lonely=True):
        f = open(path,'r')
        vertices = {}
        nodes = {}
        edges = {}
        edge_labels = {}
        c_edges = 1
        for line in f:
            if line.startswith("t"):
                pass
            if line.startswith("v"):
                sp = line.split(" ")
                v = int(sp[1])
                vertices[v] = []
                v_label = int(sp[2])
                nodes[v] = mapping[v_label] 
            if line.startswith("e"):
                #self.log.info(line)
                sp = line.split(" ")
                v1 = int(sp[1])
                v2 = int(sp[2])
                edges[tuple((v1,v2))] = 1
                edge_labels[tuple((v1,v2))] = sp[3].replace('\n','')
                c_edges = c_edges + 1
                vertices[v1].append(v2)
                vertices[v2].append(v1)
        
        if not lonely:
            #STUFF below to delete lonely nodes
            de = []
            count = 0
            vertices_ok = {}
            nodes_ok = {}
            map_clean = {}
            # find index of lonely node
            for key in vertices:
                if not vertices[key]:
                    de.append(key)
                else:
                    map_clean[key] = count
                    count = count +1
            #delete them
            for key in de:
                del vertices[key]

            for key in vertices:
                local_dic = {}
                for v in vertices[key]:
                    local_dic[map_clean[v]] = 1.0
                
                #self.log.info(local_dic)
                vertices_ok[map_clean[key]] = local_dic
                nodes_ok[map_clean[key]] = nodes[key]

            if len(vertices_ok) <= 1:
                self.log.info(vertices_ok)
            G = Graph(vertices_ok,node_labels=nodes_ok,edge_labels=edge_labels)
        else:
            
            G = Graph(vertices,node_labels=nodes,edge_labels=edge_labels)
        f.close()
        return G


    # TODO check if refactor possible with WL 
    def merge_in_gs(self,g1,g2,filename):
        #import pdb; pdb.set_trace()
        if g1==g2:
            return 1
        sameG = False
        common_edges = 0
        key_dic = str(g1.__hash__()) +'-'+ str(g2.__hash__())
        rev_key_dic = str(g2.__hash__()) +'-'+ str(g1.__hash__())
        self.log.info("key_dic : " + key_dic)
        if key_dic in self.dico_precomputed :
            self.log.info(self.dico_precomputed)
            #self.log.info(Dico_precomputed[g1.__hash__()])
            common_edges = self.dico_precomputed[key_dic]['common_edges']
        elif rev_key_dic in self.dico_precomputed :
            common_edges = self.dico_precomputed[rev_key_dic]['common_edges']
        else: 
            f = open(filename,'w')
            f.write('t # 0\n')
            #self.log.info(g1.node_labels.items())
            #self.log.info(g1.edge_labels.items())
            for key,value in g1.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
                #self.log.info("v "+str(key)+' '+str(mapping_inv[value])+'\n')
            for (v1,v2),l in g1.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
                #self.log.info("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
            #import time
            #time.sleep(100)        
                
            f.write('t # 1\n')
            for key,value in g2.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
            for (v1,v2),l in g2.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
            f.close()

            command = self.gspan_path + "gspan"
            tab_arg = command + '  --input_file '+filename+' --output_file temp2.gs --pattern --biggest_subgraphs 1 --threads 3 --timeout 1 --support 1.0'
            process = subprocess.Popen(tab_arg.split(' '))
            try:
                process.wait(timeout=90)
            except:
                process.kill()
            
            len_edges= [0]
            i=0
            for j in [0,1,2]:
                try:
                    res2 = open('temp2.gs.t'+str(j),'r')
                    for line in res2 :
                        if 't #' in line:
                            len_edges.append(0)
                        elif 'x: 0 1 ' in line:
                            i += 1
                        elif 'x: 0' in line :
                            len_edges[i] = 0
                            i += 1
                        elif 'e ' in line :
                            len_edges[i] += 1
                        else :
                            pass
                    res2.close()
                    len_edges.append(0)
                    common_edges = max(len_edges)    
                    os.system("rm temp2.gs.t"+str(j))
                except:
                    self.log.info("error common edges")

                    common_edges=max(len_edges)
        self.dico_precomputed[key_dic] =  {'common_edges':common_edges}

        self.log.info("common edges : "+str(common_edges))
        
        #### g1 
        counter1 =0
        counter2=0
        common_nodes =0
        node1 = {}
    
        if g1.__hash__() in self.dico_precomputed:
            #self.log.info(Dico_precomputed)
            #self.log.info(Dico_precomputed[g1.__hash__()])
            g1comp = self.dico_precomputed[g1.__hash__()]['gcomp']
            counter1 = self.dico_precomputed[g1.__hash__()]['counter']
        else: 
            f = open(filename,'w')
            f.write('t # 0\n')
            for key,value in g1.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
                counter1 = counter1 + 1
                if value in node1:
                    node1[value] = node1[value] +1
                else:
                    node1[value] = 1
            for (v1,v2),l in g1.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
                
                
            f.write('t # 1\n')
            for key,value in g1.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
                    
            for (v1,v2),l in g1.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
            f.close()
            command = self.gspan_path + "gspan"
            tab_arg = command + ' --input_file '+filename+' --output_file temp2.gs --pattern --biggest_subgraphs 1 --threads 4 --timeout 1 --support 1.0'
            process = subprocess.Popen(tab_arg.split(' '))
            try:
                process.wait(timeout=60)
            except:
                process.kill()

            len_edges= [0]
            i=0    
            for j in [0,1,2,3]:
                try:
                    res2 = open('temp2.gs.t'+str(j),'r')
                    for line in res2 :
                        if 't #' in line:
                            len_edges.append(0)
                        elif 'x: 0 1 ' in line:
                            i += 1
                        elif 'x: 0' in line :
                            len_edges[i] = 0
                            i += 1
                        elif 'e ' in line :
                            len_edges[i] += 1
                        else :
                            pass
                    res2.close()

                    len_edges.append(0)
                    g1comp = max(len_edges)    
                    os.system("rm temp2.gs.t"+str(j))
                except:
                    g1comp=len(g1.edge_labels)
            self.dico_precomputed[g1.__hash__()] = {'gcomp':g1comp,'counter':counter1}
        self.log.info("edges g1 : "+str(g1comp))
        #### g2
        if g2.__hash__() in self.dico_precomputed:
            g2comp = self.dico_precomputed[g2.__hash__()]['gcomp']
            counter2 = self.dico_precomputed[g2.__hash__()]['counter']
        else:    
            f = open(filename,'w')
            f.write('t # 0\n')
            for key,value in g2.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
                counter2 = counter2 + 1
                if value in node1 and node1[value] > 0:
                    common_nodes = common_nodes +1
                    node1[value] = node1[value] - 1
            for (v1,v2),l in g2.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
                
                
            f.write('t # 1\n')
            for key,value in g2.node_labels.items():
                f.write("v "+str(key)+' '+str(self.mapping_inv[value])+'\n')
            for (v1,v2),l in g2.edge_labels.items():
                f.write("e "+str(v1)+' '+str(v2)+' '+str(l)+'\n')
            f.close()
        
            command = self.gspan_path + "gspan"
            tab_arg = command + ' --input_file '+filename+' --output_file temp2.gs --pattern --biggest_subgraphs 1 --threads 4 --timeout 1 --support 1.0'
            process = subprocess.Popen(tab_arg.split(' '))
            try:
                process.wait(timeout=60)
            except:
                process.kill()
            
            
            len_edges= [0]
            i=0    
            for j in [0,1,2,3]:    
                try:
                    res2 = open('temp2.gs.t'+str(j),'r')
                    for line in res2 :
                        if 't #' in line:
                            len_edges.append(0)
                        elif 'x: 0 1 ' in line:
                            i += 1
                        elif 'x: 0' in line :
                            len_edges[i] = 0
                            i += 1
                        elif 'e ' in line :
                            len_edges[i] += 1
                        else :
                            pass
                    len_edges.append(0)
                    g2comp = max(len_edges)
                    os.system("rm temp2.gs.t"+str(j))
                    res2.close()
                except:
                    g2comp=len(g2.edge_labels)
            self.dico_precomputed[g2.__hash__()] = {'gcomp':g2comp,'counter':counter2}
        self.log.info("edges g2 : "+str(g2comp))
        
        nef = 0.25
        try:
            nodes_factor = common_nodes/(min(counter1,counter2))
            edges_factor = common_edges/(min(g1comp,g2comp))
            return min(1,nef * nodes_factor + (1-nef) * edges_factor)
        except:
            return 0


