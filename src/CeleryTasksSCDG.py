import logging
from ToolChainSCDG.ToolChainSCDG import ToolChainSCDG
from ToolChainSCDG.clogging.CustomFormatter import CustomFormatter
try:
    from .CeleryTasks import app
except:
    from CeleryTasks import app
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = ROOT_DIR.replace("tasks","")

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
log = logging.getLogger("CeleryTasksSCDG")
log.setLevel(logging.INFO)
log.addHandler(ch)
log.propagate = False

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
            args_scdg.exp_dir = args_scdg.exp_dir.replace(last_familiy,folder.split("/")[-1])
            last_familiy = folder.split("/")[-1]
            files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
            for file  in files:
                toolcl.build_scdg(args_scdg, file, expl_method,last_familiy,is_fl=True)
            families += last_familiy
    else:
        log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
        exit(-1)
    return 0