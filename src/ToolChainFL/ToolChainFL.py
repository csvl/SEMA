import celery
import os
from ..ToolChain import ToolChain

import tasks.CeleryTasksClassifier as CeleryTasksClassifier
import tasks.CeleryTasksSCDG as CeleryTasksSCDG

from HE.HE_SEALS import F
from .helper.ArgumentParserFL import ArgumentParserFL
import task

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class ToolChainFL:
    def __init__(self):
       self.tools = ToolChain()
       self.celery_task_classifier = CeleryTasksClassifier(self.tools.toolmc,self.tools.args_class)
       self.celery_task_scdg = CeleryTasksSCDG(self.tools.toolc,self.tools.args_scdg)
       self.hosts = ['host2','host3','host4']
       self.test_value = [2.1, 2.1, 2.1]    
           
    def fl_scdg(self,runname, smodel, nepoch, nround,sround=0):
        select_id = 0
        #runname = "2021-08-08_17-09-07_CDFS_10min"
        #runname = "dataset20211020new"
        args = {"n_features":2,
                "embedding_dim":64,"nepochs":2,
                "run_name":"dataset20211020new","nround":0}
        tround= sround
        while tround < nround:
            args["nround"] = tround
            job = []
            for i in range(len(self.hosts)):
                job.append(self.celery_task_scdg.train.s(**args).set(queue=self.hosts[i]))
            ret = celery.group(job)().get()
            idx= 0
            for r in ret:
                idx+=1

            args["num"] = len(self.hosts)
            args["run_name"] = f"{runname}_part{select_id}"     
            tround+=1


    def fl_classifier(self,runname, smodel, nepoch, nround,sround=0):
        his_train = list()
        for _ in self.hosts:
            his_train.append(list())
        
        job = []
        for i in range(len(self.hosts)):
            job.append(self.celery_task_classifier.initHE.s(self.test_value).set(queue=self.hosts[i]))
        ret_ctx = celery.group(job)().get()
        select_id = 0
        ctx_str = ret_ctx[select_id]["ctx"]
        test_value_enc = ret_ctx[select_id]["v"]
        
        #runname = "2021-08-08_17-09-07_CDFS_10min"
        #runname = "dataset20211020new"
        args = {"ctx":ctx_str,"n_features":2,"embedding_dim":64,"nepochs":2,"run_name":"dataset20211020new","nround":0}
        args["test"] = runname
        args["nepochs"] = nepoch
        tround= sround
        while tround < nround:
            args["nround"] = tround
            job = []
            for i in range(len(self.hosts)):
                args["run_name"] = f"{runname}_part{i}"
                args["ctx"] = ret_ctx[select_id]["ctx"]
                args["smodel"] = smodel
                job.append(self.celery_task_classifier.train.s(**args).set(queue=self.hosts[i]))
            ret = celery.group(job)().get()
            paras = list()
            idx= 0
            for r in ret:
                paras.append(r['para'])
                his_train[idx].extend(r['his']['train'])
                idx+=1
            enc_para = F.add_weight(paras,ret_ctx[select_id]["ctx"])
            #para = F.add_para(paras)
            
            
            args["para"]= enc_para
            args["v_enc"] = test_value_enc
            ctx_str0 = F.bytes_to_string(task.tasks.context.serialize())
            args["ctx"] = ctx_str0
            args["num"] = len(self.hosts)
            args["run_name"] = f"{runname}_part{select_id}"
            
            ret = celery.group(self.celery_task_classifier.decryption.s(**args).set(queue=self.hosts[select_id]))().get()
            
            enc_v = F.string_to_enc(ret[0]["v"],task.tasks.context)
            print(enc_v.decrypt(task.tasks.key))
            
            
            #para = F.decrypt_para(task.tasks.key, task.tasks.context, ret[0]["para"])
            para = ret[0]["para"]

            ### Decrypt and encrypt again before sending updates
            job=[]
            for i in range(len(self.hosts)):
                if i == select_id:
                    continue
                ctx = F.context_from_string(ret_ctx[i]["ctx"])
                args["para"]= para #F.encrypt_para(ctx, para)
                args["v_enc"] = ret_ctx[i]["v"]
                args["run_name"] = f"{runname}_part{i}"
                job.append(self.celery_task_classifier.update.s(**args).set(queue=self.hosts[i]) )
            ret = celery.group(job)().get()
            for r in ret:
                print(r)
            job=[]
            for i in range(len(self.hosts)):
                args["run_name"] = f"{runname}_part{i}"
                args["test"] = f"{runname}_part{i}" #f"{runname}"
                #args["test"] = f"{runname}"
                job.append(self.celery_task_classifier.test.s(**args).set(queue=self.hosts[i]) )
            ret = celery.group(job)().get()
            for r in ret:
                print(f"{r}")
            tround+=1
        import matplotlib.pyplot as plt
        plt.plot(his_train)
        plt.ylabel('Loss')
        plt.savefig(f"his_fig.png", bbox_inches='tight')
            
def main():
    fl = ToolChainFL()
    # TODO 
    fl.fl_scdg(args.runname, args.smodel, args.nepochs, args.nrounds,args.sround)
    fl.fl_classifier(args.runname, args.smodel, args.nepochs, args.nrounds,args.sround)

if __name__=="__main__":
    main()


