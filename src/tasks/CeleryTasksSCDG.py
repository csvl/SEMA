from re import A
from matplotlib.pyplot import cla
try:
    from .CeleryTasks import app, context, temp_path
    from .HE.HE_SEALS import F, RSA
except:
    from CeleryTasks import app, context, temp_path
    from HE.HE_SEALS import F, RSA
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = ROOT_DIR.replace("tasks","")

class CeleryTasksSCDG: 
    def __init__(self, toolcl,args_parser):
        self.toolcl = toolcl
        self.args_scdg, self.folderName, self.expl_method, self.familly = args_parser.args_parser_scdg.parse_arguments(True)
 
    @app.task
    def start_scdg(self, ** args):
        last_familiy = "unknown"
        if os.path.isdir(self.folderName):
            subfolder = [os.path.join(self.folderName, f) for f in os.listdir(self.folderName) if os.path.isdir(os.path.join(self.folderName, f))]
            print(subfolder)
            for folder in subfolder:
                print("You are currently building SCDG for " + folder)
                self.args_scdg.exp_dir = self.args_scdg.exp_dir.replace(last_familiy,folder.split("/")[-1])
                last_familiy = folder.split("/")[-1]
                files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
                for file  in files:
                    self.toolcl.build_scdg(self.args_scdg, file, self.expl_method,last_familiy)
                self.families += last_familiy
        else:
            print("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
            exit(-1)
        return 0