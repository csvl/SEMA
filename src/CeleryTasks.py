import logging
from ToolChainSCDG.ToolChainSCDG import ToolChainSCDG
from ToolChainClassifier.ToolChainClassifier import ToolChainClassifier
from ToolChainSCDG.clogging.CustomFormatter import CustomFormatter
try:
    from .HE.HE_SEALS import F, RSA
except:
    from HE.HE_SEALS import F, RSA
import os
# import pickle
import dill
import celery

# Celery config
# Client: 130.104.229.26
# Client: 130.104.229.85
IP = "130.104.229.84/qa1"  # Master node
HOST = f'rabbitmq:9a55f70a841f18b97c3a7db939b7adc9e34a0f1d@{IP}'

# HOST = 'localhost'

BROKER = f'amqp://{HOST}'
BACKEND= f'rpc://{HOST}'

app = celery.Celery('ToolChainFL', broker=BROKER, backend=BACKEND)

context, key = F.init_encrypt()
sk,pk = RSA.generate_key()

"""
celery -A task.tasks flower
ssh -i ~/.ssh/id_kdam -L 5555:130.104.229.26:5555 kdam@130.104.229.26
"""

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())


logc = logging.getLogger("CeleryTasksClassifier")
logc.setLevel(logging.INFO)
logc.addHandler(ch)
logc.propagate = False

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = ROOT_DIR.replace("tasks","")


log = logging.getLogger("CeleryTasksSCDG")
log.setLevel(logging.INFO)
log.addHandler(ch)
log.propagate = False

# SCDGs creation

@app.task
def start_scdg(** args):
    toolcl = ToolChainSCDG(print_sm_step=True,
                            print_syscall=True,
                            debug_error=True,
                            debug_string=True,
                            print_on=True,
                            is_from_tc=True)
    folderName  = args["folderName"]
    args_scdg = args["args_scdg"]
    families = args["families"]
    expl_method = args["expl_method"]
    last_familiy = "unknown"
    if os.path.isdir(folderName):
        subfolder = [os.path.join(folderName, f) for f in os.listdir(folderName) if os.path.isdir(os.path.join(folderName, f))]
        log.info(subfolder)
        for folder in subfolder:
            log.info("You are currently building SCDG for " + folder)
            args_scdg["exp_dir"] = args_scdg["exp_dir"].replace(last_familiy,folder.split("/")[-1])
            last_familiy = folder.split("/")[-1]
            files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
            for file  in files:
                toolcl.build_scdg(args_scdg, file, expl_method,last_familiy,is_fl=True)
            families += last_familiy
    else:
        log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
        exit(-1)
    return 0

# Classifier

def save_object(ob, path):
    with open(path, 'wb+') as output:
        dill.dump(ob, output)

def load_object(path):
    with open(path, 'rb') as inp:
        return dill.load(inp)

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
    pwd = ROOT_DIR
    logc.info(run_name)
        
    if nround<1:
        toolcl = ToolChainClassifier(classifier_name = "dl")
        families = []
        last_familiy = "unknown"
        if os.path.isdir(input_path):
            subfolder = [os.path.join(input_path, f) for f in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, f))]
            for folder in subfolder:
                last_familiy = folder.split("/")[-1]
                families.append(str(last_familiy))
        toolcl.init_classifer(args=args_class,families=families,is_fl=True)
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
    pwd = ROOT_DIR
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
    pwd = ROOT_DIR
    trainer = load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    trainer.modelparameters = para
    save_object(trainer, f"{run_name}_model.pkl")
    save_object(trainer, os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    return {"v":v_enc.decrypt(key)}
        
@app.task
def test(**args):
    nround = args["nround"]
    run_name  = args["run_name"]
    pwd = ROOT_DIR
    trainer = load_object(os.path.join(pwd,f"R{nround}_{run_name}_model.pkl"))
    trainer.classify()
    acc, loss = trainer.get_stat_classifier()
    return {"acc":acc, "loss":loss}

