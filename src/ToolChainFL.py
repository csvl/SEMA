from ast import parse
import celery
import os

try:
    from CeleryTasksClassifier import *
    from CeleryTasksSCDG import *
    from ToolChain import ToolChain
    from HE.HE_SEALS import F
    from helper.ArgumentParserFL import ArgumentParserFL
except:
    from .CeleryTasksClassifier import *
    from .CeleryTasksSCDG import *
    from .ToolChain import ToolChain
    from .HE.HE_SEALS import F
    from .helper.ArgumentParserFL import ArgumentParserFL

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# TODO should autodiscover hosts
class ToolChainFL:
    def __init__(self,hosts=['host2','host3'], # ,'host4']
                      test_val=[2.1, 2.1, 2.1],
                      n_features=2
                      ):
       self.tools = ToolChain()
       self.families = self.tools.families
       self.args_class = self.tools.args_class
       self.folderName = self.tools.folderName
       self.expl_method = self.tools.expl_method
       self.familly = self.tools.familly
       self.args_scdg = self.tools.args_scdg
       parser = ArgumentParserFL()
       self.args, _ = parser.parse_arguments()
       self.hosts = hosts
       if self.args.hostnames and len(self.args.hostnames) > 0:
           self.hosts = self.args.hostnames
       self.test_value = test_val
           
    def fl_scdg(self):
        args = {"args_scdg":self.args_scdg,
                "folderName":self.folderName,
                "families":self.families,
                "expl_method":self.expl_method}
        job = []
        for i in range(len(self.hosts)):
            job.append(start_scdg.s(**args).set(queue=self.hosts[i]))
        ret = celery.group(job)().get()
        idx= 0
        for r in ret:
            idx+=1

    def fl_classifier(self):
        runname = self.args.runname
        smodel = self.args.smodel
        nepochs = self.args.nepochs
        nrounds = self.args.nrounds
        sround = self.args.sround
        his_train = list()
        for _ in self.hosts:
            his_train.append(list())
        
        job = []
        for i in range(len(self.hosts)):
            job.append(initHE.s(self.test_value).set(queue=self.hosts[i]))
        ret_ctx = celery.group(job)().get()
        select_id = 0
        ctx_str = ret_ctx[select_id]["ctx"]
        test_value_enc = ret_ctx[select_id]["v"]

        if self.tools.toolmc.input_path is None:
            input_path = self.args_scdg.exp_dir
        else:
            input_path = self.tools.toolmc.input_path
        input_path = input_path.replace("unknown/","") # todo


        args = {"ctx":ctx_str,
                "n_features":2,
                "embedding_dim":64,
                "nepochs":nepochs,
                "run_name":"christophe_test",
                "nround":0,
                "test":runname,
                "input_path":input_path,
                "support":self.args_class.support,
                "ctimeout":self.args_class.ctimeout,
                "nthread":self.args_class.nthread,
                "biggest_subgraph":self.args_class.biggest_subgraph,
                "epoch":self.args_class.epoch,
                "threshold":self.args_class.threshold}
        
        tround = sround
        while tround < nrounds:
            args["nround"] = tround
            job = []
            for i in range(len(self.hosts)):
                args["run_name"] = f"{runname}_part{i}"
                args["ctx"] = ret_ctx[select_id]["ctx"]
                args["smodel"] = smodel
                job.append(train.s(**args).set(queue=self.hosts[i]))
            ret = celery.group(job)().get()
            paras = list()
            idx= 0
            for r in ret:
                paras.append(r['para'])
                his_train[idx].extend(r['his']['train'])
                idx+=1
            enc_para = F.add_weight(paras,ret_ctx[select_id]["ctx"])
            #para = F.add_para(paras)
        
            args["para"] = enc_para
            args["v_enc"] = test_value_enc
            ctx_str0 = F.bytes_to_string(context.serialize())
            args["ctx"] = ctx_str0
            args["num"] = len(self.hosts)
            args["run_name"] = f"{runname}_part{select_id}"
            
            ret = celery.group(decryption.s(**args).set(queue=self.hosts[select_id]))().get()
            
            enc_v = F.string_to_enc(ret[0]["v"],context)
            print(enc_v.decrypt(key))
        
            #para = F.decrypt_para(key, context, ret[0]["para"])
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
                job.append(update.s(**args).set(queue=self.hosts[i]) )
            ret = celery.group(job)().get()
            for r in ret:
                print(r)

            job=[]
            for i in range(len(self.hosts)):
                args["run_name"] = f"{runname}_part{i}"
                args["test"] = f"{runname}_part{i}" #f"{runname}"
                #args["test"] = f"{runname}"
                job.append(test.s(**args).set(queue=self.hosts[i]) )
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
    #fl.fl_scdg()
    fl.fl_classifier()

if __name__=="__main__":
    main()


