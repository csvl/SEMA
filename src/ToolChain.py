import os
import time
from re import sub
import logging
from ToolChainClassifier.ToolChainClassifier import ToolChainClassifier
from ToolChainSCDG.ToolChainSCDG import ToolChainSCDG
from helper.ArgumentParserTC import ArgumentParserTC
from ToolChainSCDG.clogging.CustomFormatter import CustomFormatter

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class ToolChain:
    def __init__(self):
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("ToolChain")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False

        self.start_time = time.time()

        self.toolc = ToolChainSCDG(
            print_sm_step=True,
            print_syscall=True,
            debug_error=True,
            debug_string=True,
            print_on=True,
            is_from_tc=True
        )
        
        self.toolmc = ToolChainClassifier()

        args_parser = ArgumentParserTC(self.toolc, self.toolmc)
        self.args_scdg, self.folderName, self.expl_method, self.familly = args_parser.args_parser_scdg.parse_arguments(True)
        self.args_class  = args_parser.args_parser_class.parse_arguments(True)

        self.families = []
      
    def start_scdg(self):
        last_familiy = "unknown"
        if os.path.isdir(self.folderName):
            subfolder = [os.path.join(self.folderName, f) for f in os.listdir(self.folderName) if os.path.isdir(os.path.join(self.folderName, f))]
            self.log.info(subfolder)
            for folder in subfolder:
                self.log.info("You are currently building SCDG for " + folder)
                self.args_scdg.exp_dir = self.args_scdg.exp_dir.replace(last_familiy,folder.split("/")[-1])
                last_familiy = folder.split("/")[-1]
                files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
                for file  in files:
                    self.toolc.build_scdg(self.args_scdg, file, self.expl_method,last_familiy)
                self.families += last_familiy
        else:
            self.log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
            exit(-1)
    
    def start_training(self):
        if self.toolmc.input_path is None:
            input_path = self.args_scdg.exp_dir
        else:
            input_path = self.toolmc.input_path
        input_path = input_path.replace("unknown/","") # todo
        self.families = []
        last_familiy = "unknown"
        if os.path.isdir(input_path):
            subfolder = [os.path.join(input_path, f) for f in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, f))]
            self.log.info(subfolder)
            for folder in subfolder:
                last_familiy = folder.split("/")[-1]
                self.families.append(str(last_familiy))

        self.toolmc.init_classifer(args=self.args_class,families=self.families)
        if self.toolmc.input_path is None:
            print(input_path)
            self.toolmc.classifier.train(input_path)
        else:
            self.toolmc.classifier.train(self.toolmc.input_path)

    def start_classify(self):
        if self.toolmc.classifier.dataset_len > 0:
            self.toolmc.classifier.classify()
            if self.toolmc.classifer_name == "gspan":
                self.toolmc.classifier.get_stat_classifier(target=self.toolmc.mode)
            else:
                self.toolmc.classifier.get_stat_classifier()

def main():
    tc = ToolChain()
    tc.start_scdg()
    tc.start_training()
    tc.start_classify()
    elapsed_time = time.time() - tc.start_time
    tc.log.info("Total execution time: " + str(elapsed_time))

if __name__ == "__main__":
    main()
