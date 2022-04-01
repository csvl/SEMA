from matplotlib.pyplot import cla
from ...ToolChainClassifier.classifier.DL import DLDataset, DLTrainerClassifier
from CeleryTasks import CeleryTasks
from ..HE.HE_SEALS import F, RSA

#from . import temp_path
from torch.utils.data import DataLoader
from torch.utils.data import random_split
import os
import pickle
import celery
from ..ToolChainFL import ROOT_DIR


class CeleryTasksClassifier(CeleryTasks):
    def __init__(self, toolcl,args):
        self.toolcl = toolcl
        if self.toolcl.input_path is None:
            self.input_path = ROOT_DIR.replace("ToolChainFL","output/save-SCDG") # todo add args
        else:
            self.input_path = self.toolcl.input_path
        self.args_class = args

    def save_object(self,ob, path):
        with open(path, 'wb') as output:
            pickle.dump(ob, output)

    def load_object(self,path):
        with open(path, 'rb') as inp:
            return pickle.load(inp)

    @CeleryTasks.app.task
    def initHE(self,v):
        import tenseal as ts
        v_enc = ts.ckks_vector(CeleryTasks.context,v)
        pem = RSA.serialize_pk(self.pk)
        return {"ctx":F.enc_to_string(CeleryTasks.context),"v":F.enc_to_string(v_enc), "pk": F.bytes_to_string(pem)}

    @CeleryTasks.app.task
    def train(self, ** args):
        ctx = F.string_to_bytes(args["ctx"])
        run_name  = args["run_name"]
        nround = args["nround"]
        pwd = os.path.join(CeleryTasks.temp_path,run_name)   
        print(run_name)
        
        if nround<1:
            self.families = []
            last_familiy = "unknown"
            if os.path.isdir(self.input_path):
                subfolder = [os.path.join(self.input_path, f) for f in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, f))]
                self.log.info(subfolder)
                for folder in subfolder:
                    last_familiy = folder.split("/")[-1]
                    self.families.append(str(last_familiy))
            self.toolmc.init_classifer(args=self.args_class,families=self.families)
            trainer = self.toolcl.classifier
        else:
            trainer = self.load_object(os.path.join(pwd,f"R{nround-1}_{run_name}_model.pkl"))
        
        model, his = trainer.train(self.input_path)
        
        self.save_object(trainer, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        
        """
        test_path = os.path.join(temp_path,args["test"])
        data = Dataset(os.path.join(test_path,"dataset_test.hdf5"))
        test_loader = DataLoader(data, batch_size=1,num_workers=0)
        acc_loss = trainer.test(test_loader)
        """
        
        para = F.encrypt_weight(ctx,trainer.share_model)
        #para = trainer.get_model_parameter()
        #return {"para":para,"his":his,"ctx":args["ctx"], "acc":acc_loss[0], "loss":acc_loss[1]}
        return {"para":para,"his":his}

    @CeleryTasks.app.task
    def decryption(self,**args):
        import tenseal as ts
        run_name  = args["run_name"]
        para = args["para"]
        ctx = args["ctx"]
        nround = args["nround"]
        num = float(args["num"])
        pwd =os.path.join(CeleryTasks.temp_path,run_name)
        t = self.load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        t.share_model = F.update_encrypt(self.key,CeleryTasks.context,para, num, t.share_model)
        self.save_object(t, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        para = t.get_model_parameter()
        """
        para =[]
        for p in t.modelparameters:
            v = p.flatten().tolist()
            para.append(v)
        """
            
        ctx = F.string_to_bytes(args["ctx"])
        v_enc =  F.string_to_enc(args["v_enc"],CeleryTasks.context)
        v = v_enc.decrypt(self.key)
        v_enc = ts.ckks_vector(ts.context_from(ctx),v)
        
        return {"v":F.enc_to_string(v_enc), "para": para}
        
    @CeleryTasks.app.task
    def update(self,**args):
        run_name  = args["run_name"]
        para = args["para"]
        v_enc = F.string_to_enc(args["v_enc"],CeleryTasks.context)
        num = 1.0
        nround = args["nround"]
        pwd =os.path.join(CeleryTasks.temp_path,run_name)
        t = self.load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        t.modelparameters = para
        self.save_object(t, f"{run_name}_model.pkl")
        self.save_object(t, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        return {"v":v_enc.decrypt(self.key)}
        
    @CeleryTasks.app.task
    def test(self,**args):
        nround = args["nround"]
        run_name  = args["run_name"]
        pwd =os.path.join(CeleryTasks.temp_path,run_name)
        t = self.load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        t.classify()
        acc, loss = t.get_stat_classifier()
        return {"acc":acc, "loss":loss}
