import imp
from matplotlib.pyplot import cla

from ToolChainClassifier.ToolChainClassifier import ToolChainClassifier
try:
    from .CeleryTasks import app, context, temp_path, pk, key
    from .HE.HE_SEALS import F, RSA
except:
    from CeleryTasks import app, context, temp_path, pk, key
    from HE.HE_SEALS import F, RSA
import os
import pickle

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = ROOT_DIR.replace("tasks","")

def save_object(ob, path):
    with open(path, 'wb') as output:
        pickle.dump(ob, output)

def load_object(path):
    with open(path, 'rb') as inp:
        return pickle.load(inp)

@app.task
def initHE( v):
    import tenseal as ts
    v_enc = ts.ckks_vector(context,v)
    pem = RSA.serialize_pk(pk)
    return {"ctx":F.enc_to_string(context),"v":F.enc_to_string(v_enc), "pk": F.bytes_to_string(pem)}

@app.task
def train(** args):
    ctx = F.string_to_bytes(args["ctx"])
    run_name  = args["run_name"]
    nround = args["nround"]
    input_path = args["input_path"]
    args_class = args["args_class"]


    pwd = os.path.join(temp_path,run_name)   
    print(run_name)
        
    if nround<1:
        toolcl = ToolChainClassifier()
        families = []
        last_familiy = "unknown"
        toolcl.classifer_name = "dl"
        if os.path.isdir(input_path):
            subfolder = [os.path.join(input_path, f) for f in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, f))]
            for folder in subfolder:
                last_familiy = folder.split("/")[-1]
                families.append(str(last_familiy))
        toolcl.init_classifer(args=args_class,families=families)
        trainer = toolcl.classifier
    else:
        trainer = load_object(os.path.join(pwd,f"R{nround-1}_{run_name}_model.pkl"))
        
    model, his = trainer.train(input_path)
        
    save_object(trainer, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
        
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

@app.task
def decryption(**args):
    import tenseal as ts
    run_name  = args["run_name"]
    para = args["para"]
    ctx = args["ctx"]
    nround = args["nround"]
    num = float(args["num"])
    pwd =os.path.join(temp_path,run_name)
    trainer = load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    trainer.share_model = F.update_encrypt(key,context,para, num, trainer.share_model)
    save_object(trainer, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    para = trainer.get_model_parameter()
    """
    para =[]
    for p in t.modelparameters:
        v = p.flatten().tolist()
        para.append(v)
    """
            
    ctx = F.string_to_bytes(args["ctx"])
    v_enc =  F.string_to_enc(args["v_enc"],context)
    v = v_enc.decrypt(key)
    v_enc = ts.ckks_vector(ts.context_from(ctx),v)
        
    return {"v":F.enc_to_string(v_enc), "para": para}
        
@app.task
def update(**args):
    run_name  = args["run_name"]
    para = args["para"]
    v_enc = F.string_to_enc(args["v_enc"],context)
    num = 1.0
    nround = args["nround"]
    pwd =os.path.join(temp_path,run_name)
    trainer = load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    trainer.modelparameters = para
    save_object(trainer, f"{run_name}_model.pkl")
    save_object(trainer, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    return {"v":v_enc.decrypt(key)}
        
@app.task
def test(**args):
    nround = args["nround"]
    run_name  = args["run_name"]
    pwd = os.path.join(temp_path,run_name)
    trainer = load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    trainer.classify()
    acc, loss = trainer.get_stat_classifier()
    return {"acc":acc, "loss":loss}
