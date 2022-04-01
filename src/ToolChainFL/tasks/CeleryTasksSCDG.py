from re import A
from matplotlib.pyplot import cla
from ..HE.HE_SEALS import F, RSA
from CeleryTasks import CeleryTasks
import os
from ..ToolChainFL import ROOT_DIR


class CeleryTasksSCDG(CeleryTasks): 
    def __init__(self, toolcl,args):
        self.toolcl = toolcl
        if self.toolcl.input_path is None:
            self.input_path = ROOT_DIR.replace("ToolChainFL","output/save-SCDG") # todo add args
        else:
            self.input_path = self.toolcl.input_path
        self.args_scdg = args

    @CeleryTasks.app.task
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
                    self.toolc.build_scdg(self.args_scdg, file, self.expl_method,last_familiy)
                self.families += last_familiy
        else:
            print("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
            exit(-1)
        return 0