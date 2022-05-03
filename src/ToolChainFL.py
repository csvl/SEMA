from ast import parse
import logging
import celery
import os

from matplotlib.pyplot import cla
from numpy import double
from ToolChainSCDG.clogging.CustomFormatter import CustomFormatter
from ToolChainClassifier.ToolChainClassifier import ToolChainClassifier
from ToolChainSCDG.ToolChainSCDG import ToolChainSCDG
try:
    from CeleryTasks import *
    from HE.HE_SEALS import F
    from helper.ArgumentParserFL import ArgumentParserFL
except:
    from .CeleryTasks import *
    from .HE.HE_SEALS import F
    from .helper.ArgumentParserFL import ArgumentParserFL

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# TODO should autodiscover hosts
# TODO add logger in file for master node 
class ToolChainFL:
    def __init__(self,hosts=['host2','host3'], # ,'host4']
                      test_val=[2.1, 2.1, 2.1],
                      ):
        self.tool_scdg = ToolChainSCDG(
            print_sm_step=True,
            print_syscall=True,
            debug_error=True,
            debug_string=True,
            print_on=True,
            is_from_tc=True
        )
        self.families = []
        self.tool_classifier = ToolChainClassifier(parse=False)
        
        self.args_parser = ArgumentParserFL(self.tool_scdg, self.tool_classifier)
        self.args = self.args_parser.parse_arguments()
        self.tool_classifier.args = self.args
        self.args_parser.args_parser_scdg.update_tool(self.args)
        self.args_parser.args_parser_class.update_tool(self.args)
        self.args.exp_dir = self.args.binaries
        self.args.dir = self.args.binaries

        self.hosts = hosts
        if self.args.hostnames and len(self.args.hostnames) > 0:
            self.hosts = self.args.hostnames
        self.test_value = test_val
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("ToolChainFL")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        output_file_handler = logging.FileHandler("logs/ToolChainFL.log") # TODO path
        self.log.addHandler(output_file_handler)
        self.log.propagate = False

    def fl_scdg(self):
        self.log.info("Starting SCDGs phase in FL")
        args = {"args_scdg":self.args.__dict__}
        job = []
        for i in range(len(self.hosts)):
            args["client_id"] = i+1
            job.append(start_scdg.s(**args).set(queue=self.hosts[i]))
        ret = celery.group(job)().get()
        self.log.info("Ending SCDGs phase in FL")

    def fl_classifier(self):
        self.log.info("Starting classification phase in FL")
        classifier = self.args.classifier

        if classifier is None:
            classifier = "dl"
        elif classifier not in ["dl","gspan"]:
            # Note gspan still in progression
            self.log.info("Only deep learning model and GSpan allowed in federated learning mode")
            exit(-1)
        
        his_train = list()  # for expiments measure purposes
        for _ in self.hosts:
            his_train.append(list())
        
        job = []
        for i in range(len(self.hosts)):
            job.append(initHE.s(self.test_value).set(queue=self.hosts[i]))
        ret_ctx = celery.group(job)().get()
        select_id = 0
        ctx_str = ret_ctx[select_id]["ctx"]      # client public key
        test_value_enc = ret_ctx[select_id]["v"]

        if self.tool_classifier.input_path is None:
            input_path = self.args_scdg.exp_dir
        else:
            input_path = self.tool_classifier.input_path
        input_path = input_path.replace("unknown/","") # todo
        
        args = {"ctx":ctx_str, # TODO extract from arg parser DAM
                "n_features":2,
                "embedding_dim":64,
                "nepochs":1,        # always 1
                "run_name":self.args.run_name,
                "nround":self.args.nrounds,
                "input_path":input_path,
                "demonstration":self.args.demonstration,
                "smodel":self.args.smodel,
                "classifier":classifier,
                "args_class":self.args.__dict__}
        
        tround = self.args.sround 
        if classifier == "gspan": # TODO put that in argument parser
            self.args.nrounds = 1
        while tround < self.args.nrounds:
            self.log.info("-- Training phase in FL - round " + str(tround+1) + "/" +  str(self.args.nrounds))
            args["nround"] = tround
            job = []
            for i in range(len(self.hosts)):
                args["run_name"] = f"{self.args.run_name}_part{i}"
                args["ctx"] = ret_ctx[select_id]["ctx"]
                args["client_id"] = i+1
                args["master_pk"] = ret_ctx[select_id]["pk"]
                job.append(train.s(**args).set(queue=self.hosts[i]))
            ret = celery.group(job)().get()
            paras = list()
            idx= 0
            client_pks = list()
            for r in ret:
                if classifier == "dl":
                    self.log.info("Return value for train step: " + str(r["his"]))
                    paras.append(r['para'])
                    his_train[idx].extend(r['his']['train'])
                    idx+=1
                elif classifier == "gspan":
                    self.log.info("Return value for train step: ")
                    paras.append(r['para'])
                    client_pks.append(r['client_pk'])

            if classifier == "dl":
                # Aggragator = Master node = select_id
                enc_para = F.add_weight(paras,ret_ctx[select_id]["ctx"])
                args["para"] = enc_para
                args["v_enc"] = test_value_enc
                ctx_str0 = F.bytes_to_string(context.serialize())
                args["ctx"] = ctx_str0
                args["num"] = len(self.hosts)
                args["run_name"] = f"{self.args.run_name}_part{select_id}"
                # select_id = KEY master node
                ret = celery.group(decryption.s(**args).set(queue=self.hosts[select_id]))().get()
                enc_v = F.string_to_enc(ret[0]["v"],context)
                self.log.info("Decrypt key: "+ str(enc_v.decrypt(key)))
                #para = F.decrypt_para(key, context, ret[0]["para"])
                para = ret[0]["para"]
                ### Decrypt and encrypt again before sending updates
                job=[]
                self.log.info("-- Update phase in FL - round " + str(tround+1) + "/" +  str(self.args.nrounds))
                for i in range(len(self.hosts)):
                    if i == select_id:
                        continue
                    ctx = F.context_from_string(ret_ctx[i]["ctx"])
                    args["para"]  = para #F.encrypt_para(ctx, para) # TODO should be encrypted
                    args["v_enc"] = ret_ctx[i]["v"] 
                    args["run_name"] = f"{self.args.run_name}_part{i}"
                    job.append(update.s(**args).set(queue=self.hosts[i]))
                ret = celery.group(job)().get()
                for r in ret:
                    self.log.info("Return value for update step: " + str(r))


            elif classifier == "gspan":
                self.log.info("-- Best signature selection phase FL")
                args["select_id"] = select_id
                args["paras"] = paras
                args["client_pks"] = client_pks
                args["run_name"] = f"{self.args.run_name}_part{select_id}"
                ret = celery.group(best_signature_selection.s(**args).set(queue=self.hosts[select_id]))().get()
               
                self.log.info("-- Distribution of the best signature selection phase FL")
                job=[]
                # TODO +- useless
                for i in range(len(self.hosts)):
                    args["enc_best_sig_string"] = ret[0]["enc_best_sig_string"]
                    args["idx"] = i
                    job.append(save_sig.s(**args).set(queue=self.hosts[i]))
                ret = celery.group(job)().get()
                for r in ret:
                    self.log.info(f"{r}")

            self.log.info("-- Testing phase in FL - round " + str(tround+1) + "/" +  str(self.args.nrounds))
            # Should all have the same test set -> we assume all client have the same test set
            # TODO may be only do this on master node -> easier for deployement
            # But less good when swithing to fully decentralized architecture
            # Now we test on client  (useless for gpsan?)
            job=[]
            for i in range(len(self.hosts)):
                if classifier == "dl":
                    args["run_name"] = f"{self.args.run_name}_part{i}"
                    args["test"] = f"{self.args.run_name}_part{i}" #f"{runname}"
                    # args["test"] = f"{runname}"
                elif classifier == "gspan":
                    args["sigpath"] = None # use standard sig folder
                    args["run_name"] = f"{self.args.run_name}_part{i}"
                job.append(test.s(**args).set(queue=self.hosts[i]))
            ret = celery.group(job)().get()
            for r in ret:
                self.log.info(f"{r}")
            tround+=1
            
            if classifier == "dl":
                import matplotlib.pyplot as plt
                plt.plot(his_train)
                plt.ylabel('Loss')
                plt.savefig(f"his_fig.png", bbox_inches='tight')

        self.log.info("Ending classification phase in FL")

# TODO add FL stop procedure 
def main():
    fl = ToolChainFL()
    if not fl.args.no_scdg_create:
        fl.fl_scdg() 
    fl.fl_classifier()

if __name__=="__main__":
    main()


