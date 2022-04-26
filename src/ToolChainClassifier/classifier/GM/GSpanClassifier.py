import logging
import os,glob
import random,re
from subprocess import PIPE

from psutil import Popen
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import progressbar

try:
    from ..Classifier import Classifier
    from clogging.CustomFormatter import CustomFormatter
except:
    from ..Classifier import Classifier
    from ...clogging.CustomFormatter import CustomFormatter
        

class GSpanClassifier(Classifier):
    def __init__(self,path,threshold=0.45, support=0.75,
                      biggest_subgraphs=5, thread=5, timeout=3): # Init : 0.75, 5
        super().__init__(path,'Gspan', threshold)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("GSpanClassifier")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False
        
        if '/' not in path:
            path = path +'/'
        self.path_sig = path+'/sig/'
        self.path_test = path.replace("ToolChainClassifier","output/") +'/test-set/'
        self.path_clean = path.replace("ToolChainClassifier","output/") +'/clean/'
        self.families = []
        self.support = support
        self.biggest_subgraphs = biggest_subgraphs
        self.thread = thread
        self.timeout = timeout
        self.class_only = True
        self.predictions = []
        self.predictions_clean = []

        self.dataset_len = 1 # todo
        
        try: 
            os.mkdir(self.path_sig)
            #os.mkdir(self.path_test)
        except:
            import shutil
            shutil.rmtree(self.path_sig)
            #shutil.rmtree(self.path_test)
            
            os.mkdir(self.path_sig)
            #os.mkdir(self.path_test)
        
        
    def add_clean(self,path):
        for clean_file in glob.glob(path+"/*") :
            name = clean_file.split("/")[-1]        
            os.system("cp "+clean_file+" "+self.path_clean+name)
             
    def train(self,path):
        self.log.info("Input Path = " + path)
        if path[-1] != "/":
            path += "/"
        families = glob.glob(path+"/*")
        bar = progressbar.ProgressBar(max_value=len(families))
        bar.start()
        cnt = 0
        # Go through each directory
        for family_dir in families:
            family_name = family_dir.split('/')[-1].split('_')[0] # TODO only consider folder
            self.log.info("Family = " + family_name)
            self.families.append(family_name)
            # todo handle exception
            graph_test = random.sample(glob.glob(family_dir+"/*"), (len(glob.glob(family_dir+"/*"))//4)+1)
            
            id_graph = 0
            merge_graph = self.path_sig+family_name+'_merge.gs'
            #self.log.info("Merge_graph = " + merge_graph)
            res = open(merge_graph,'w')
            out_name = self.path_sig+family_name+'_sig.gs'
            #self.log.info("Out_name = " + out_name)
            try:
                os.mkdir(self.path_test+family_name)
            except:
                pass
            for malware_file in glob.glob(family_dir+"/*") :
                if malware_file.endswith(".gs"):
                    if malware_file in graph_test:
                        os.system("cp "+malware_file+" "+self.path_test+family_name)
                    else :
                        #self.log.info("Malware_file = " + malware_file)
                        f = open(malware_file,'r')
                        fstat = os.stat(malware_file)
                        if fstat.st_size > 60 :
                            for line in f :
                                if 't #' in line:
                                    res.write('t # '+str(id_graph)+'\n')
                                    id_graph += 1
                                else :
                                    res.write(line)
                        f.close()
            res.close()

            command = self.gspan_path + "gspan " + '--input_file '+self.path_sig+family_name+'_merge.gs --output_file '+out_name + \
                    ' --pattern --biggest_subgraphs ' + str(self.biggest_subgraphs) + \
                    ' --threads ' + str(self.thread) + \
                    ' --timeout  ' + str(self.timeout) + \
                    ' --support ' + str(self.support)

            self.log.info("Gspan_path = " + command)
            process = Popen(command, shell=True,stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            self.log.info(stdout)
            self.log.info(stderr)
            
            #We know have /sig feed with merge of .gs  and /test with some samples
                    
            files = []
            for i in range(5):
                if os.path.isfile(out_name+'.t'+str(i)):        
                    file = open(out_name+'.t'+str(i),'r')
                    files.append(file)

            sig = open(out_name,'w')
            buf_temp_f =[]
            len_file = []
            n_file = 0
            counter = 0
            for res_file in files :
                for line in res_file :
                    if 't #' in line:
                        buf_temp_f.append([])
                        counter = 0
                        #f_temp_f[n_file].write('t # '+str(n_file))
                    elif 'x: ' in line:
                        len_file.append(counter)
                        n_file += 1
                    elif 'e ' in line :
                        buf_temp_f[n_file].append(line)
                        counter +=1
                    elif 'v ' in line :
                        buf_temp_f[n_file].append(line)
                    else :
                        pass
            for f in files:
                f.close()
                if os.path.isfile(f.name):
                    os.remove(f.name)

            N_MAX = 5 # TODO
            if len(len_file) > 0:
                for i in range(N_MAX):
                    id_max = len_file.index(max(len_file))
                    sig.write('t # '+str(i)+'\n')
                    sig.write(''.join(l for l in buf_temp_f[id_max]))
                    len_file[id_max] = -1
            sig.close()
            cnt += 1
            bar.update(cnt)
        bar.finish() 
            
    def classify(self, path=None, custom_sig_path=None):
        input_path = self.path_test if path is None else path
        path_sig = self.path_sig if custom_sig_path is None else custom_sig_path
        predictions = []
        bar = progressbar.ProgressBar(max_value=len(self.families)) # TODO update
        bar.start()
        cnt = 0
        for family in self.families:
            #Iterate through samples of the family to classify
            for test_input in glob.glob(input_path+family+'/*'):
                score = []
                fam_tar = []
                #Iterate through signature to test in order to classify samples
                for signature in glob.glob(path_sig+'*_sig.gs'):
                    try:
                        sim = self._calculate_sim(test_input,signature)
                        score.append(sim)
                    except Exception as e:
                        self.log.info(e)
                        score.append(0)
                    
                    #fam_tar.append(re.findall(r"(?<=\/).*(?=_)",signature.split('/')[-1])[0])
                    fam_tar.append(signature.split('/')[-1].split('_')[0])
                
                max_score = [i for i, x in enumerate(score) if x == max(score)]
                self.log.info(max_score)
                self.log.info(score)
                if score[max_score[0]] >= self.threshold or (self.class_only):
                    best_fam = [fam_tar[s] for s in max_score]
                    #max_score = max(score)
                    #best_fam = fam_tar[score.index(max_score)]
                    predictions.append([random.choice(best_fam),family,score[max_score[0]]])
                else:
                    predictions.append(['clean',family,score[max_score[0]]])
                #bar.update(cnt) # TODO update with families of test set, error for FL
                cnt += 1
        bar.finish() 
        self.predictions = predictions
        if path is None:
            self.log.info(predictions)
        else:
            print("Prediction:")
            print(predictions)
        return predictions

    def detection(self, path=None, custom_sig_path=None):
        input_path = self.path_clean if path is None else path
        path_sig = self.path_sig if custom_sig_path is None else custom_sig_path
        predictions = []
        test_inputs = glob.glob(input_path+'/*')
        bar = progressbar.ProgressBar(max_value=len(test_inputs))
        bar.start()
        cnt = 0
        #Iterate through samples of cleanware to classify
        for test_input in test_inputs:
            score = []
            fam_tar = []
            #Iterate through signature to test in order to classify samples
            for signature in glob.glob(path_sig+'*_sig.gs'):
                try:
                    sim = self._calculate_sim(test_input,signature)
                    score.append(sim)
                except:
                    score.append(0)
                
                #fam_tar.append(re.findall(r"(?<=\/).*(?=_)",signature.split('/')[-1])[0])
                fam_tar.append(signature.split('/')[-1].split('_')[0])
            
            max_score = [i for i, x in enumerate(score) if x == max(score)]
            self.log.info(max_score)
            self.log.info(score)
            if score[max_score[0]] >= self.threshold:
                best_fam = [fam_tar[s] for s in max_score]
                predictions.append([random.choice(best_fam),'clean',score[max_score[0]]])
            #max_score = max(score)
            #best_fam = fam_tar[score.index(max_score)]
            else:
                predictions.append(["clean","clean",score[max_score[0]]])
            #bar.update(cnt) TODO
            cnt += 1
        bar.finish()
        self.predictions_clean = predictions
        if path is None:
            self.log.info(predictions)
        else:
            print("Prediction:")
            print(predictions)
        return predictions
    
    def _calculate_sim(self,in_file,sig):
        N_GRAPH = 5
        tab_similarity = [0 for index in range(N_GRAPH)]

        for sig_index in range(N_GRAPH):
            i = 0
            n_edges = 0
            f0 = open(sig,'r')
            f1 = open(in_file,'r')
            res = open('temp.gs','w')
            curr = 0
            in_ok = False
            for line in f0 :
                if in_ok and 't #' in line :
                    break
                elif 't #' in line and sig_index == curr:
                    res.write('t # '+str(i)+'\n')
                    i += 1
                    in_ok = True
                elif 't #' in line and sig_index != curr:
                    curr +=1
                elif 'e ' in line and in_ok:
                    n_edges +=1
                    res.write(line)
                elif in_ok:
                    res.write(line)
                else :
                    pass
            f0.close()
            for line in f1 :
                if 't #' in line:
                    res.write('t # '+str(i)+'\n')
                    i += 1
                else :
                    res.write(line)
            f1.close()
            res.close()

            # todo customize
            command = self.gspan_path + "gspan --input_file temp.gs --output_file temp2.gs -pattern --biggest_subgraphs 1 --threads 1 --timeout 5 --support 1.0" 
            process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()
            self.log.info(stdout)
            self.log.info(stderr)


            res2 = open('temp2.gs.t0','r')

            len_edges= []
            id = 0
            for line in res2 :
                if 't #' in line:
                    len_edges.append(0)
                elif 'x: 0 1 ' in line:
                    id += 1
                elif 'x: 0' in line :
                    len_edges[id] = 0
                    id += 1
                elif 'e ' in line :
                    len_edges[id] += 1
                else :
                    pass
            len_edges.append(0)

            res2.close()
            self.log.info('In original signature, there are '+str(n_edges)+' edges \n')
            self.log.info('After gspan, common subgraph has '+ str(max(len_edges))+' edges \n')
            self.log.info(len_edges)
            self.log.info('similarity :\n')
            try:
                self.log.info(max(len_edges)/n_edges)
                tab_similarity[sig_index] = max(len_edges)/n_edges
            except:
                tab_similarity[sig_index] = 0
            len_edges=[]
            os.remove('temp.gs')
            os.remove('temp2.gs.t0')
            return max(tab_similarity)
    

    def get_stat_classifier(self,target='classification'):
        if target == 'classification' and not self.predictions:
            self.log.info('Need to classify first\n')
            return
        elif target == 'detection' and not self.predictions_clean:
            self.log.info('Need to classify cleanwares first\n')
            return    
        elif target not in ['classification','detection']:
            self.log.info('Not valid target\n')
            return
        else :
            pass
        
        dico ={self.families[i]: i for i in range(len(self.families))}
        sample_per_family = [0 for i in range(len(self.families))]
        tp = [0 for i in range(len(self.families))]
        fp = [0 for i in range(len(self.families))]
        conf_matrix = [[0 for i in range(len(self.families))] for i in range(len(self.families))]
        
        for i in range(len(self.predictions)):
            tab = self.predictions[i]
            sample_per_family[dico[tab[1]]] += 1
            if tab[0] == tab[1]:
                tp[dico[tab[1]]] += 1
            else :
                fp[dico[tab[0]]] += 1
            conf_matrix[dico[tab[1]]][dico[tab[0]]] += 1
        
        total_sample = sum(sample_per_family)
        precision = []
        recall = []
        for i in range(len(self.families)):
            if (tp[i]+fp[i]) != 0:
                precision = precision + [(tp[i]/(tp[i]+fp[i]))*sample_per_family[i]/total_sample]
            else :
                precision = precision + [0]
            if sample_per_family[i] !=0:
                recall = recall + [(tp[i]/sample_per_family[i])*sample_per_family[i]/total_sample]
            else : 
                recall = recall + [0]
        precision = sum(precision)
        recall = sum(recall)
        fscore = (2* precision * recall)/(precision + recall)
        self.log.info("Precision obtained : "+str(precision))
        self.log.info("Recall obtained : "+str(recall))
        self.log.info("Fscore obtained : "+str(fscore))
        
        figsize = (10,7)
        fontsize=9
        fig = plt.figure(figsize=figsize)
        try:
            df_cm = pd.DataFrame(conf_matrix, index=self.families, columns=self.families,)
            heatmap = sns.heatmap(df_cm, annot=True, fmt="d",cbar=False)
        except ValueError:
            raise ValueError("Confusion matrix values must be integers.")
        heatmap.yaxis.set_ticklabels(heatmap.yaxis.get_ticklabels(), rotation=0, ha='right', fontsize=fontsize)
        heatmap.xaxis.set_ticklabels(heatmap.xaxis.get_ticklabels(), rotation=45, ha='right', fontsize=fontsize)
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        plt.show()
        return fscore

