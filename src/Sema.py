import os
import time
from re import sub
import logging
import progressbar
import glob
try:
    from SemaClassifier.SemaClassifier import SemaClassifier
    from SemaSCDG.SemaSCDG import SemaSCDG
    from helper.ArgumentParserTC import ArgumentParserTC
    from SemaSCDG.clogging.CustomFormatter import CustomFormatter
except:
    from src.SemaClassifier.SemaClassifier import SemaClassifier
    from src.SemaSCDG.SemaSCDG import SemaSCDG
    from src.helper.ArgumentParserTC import ArgumentParserTC
    from src.SemaSCDG.clogging.CustomFormatter import CustomFormatter

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class Sema:
    def __init__(self, is_from_tc=True, is_from_web=False):
        # ch = logging.StreamHandler()
        # ch.setLevel(logging.INFO)
        # ch.setFormatter(CustomFormatter())
        # self.log = logging.getLogger("Sema")
        # self.log.setLevel(logging.INFO)
        # self.log.addHandler(ch)
        # self.log.propagate = False

        self.start_time = time.time()

        self.tool_scdg = SemaSCDG(
            print_sm_step=True,
            print_syscall=True,
            debug_error=True,
            debug_string=True,
            print_on=True,
            is_from_tc=is_from_tc,
            is_from_web=is_from_web,
        )
        
        self.tool_classifier = SemaClassifier(parse=False)
        self.args_parser = ArgumentParserTC(self.tool_scdg, self.tool_classifier)        
        if is_from_web:
            self.current_exp_dir = 0
            self.tool_scdg.current_exp_dir = 0
        else:
            self.args = self.args_parser.parse_arguments()
            self.tool_classifier.args = self.args
            self.args_parser.args_parser_scdg.update_tool(self.args)
            self.args_parser.args_parser_class.update_tool(self.args)
            self.families = []
            self.args.exp_dir = self.args.binaries
            self.args.dir = self.args.binaries
            self.current_exp_dir = len(glob.glob(self.args.exp_dir + "/*")) + 1
            self.tool_scdg.current_exp_dir = self.current_exp_dir
        
def main():
    sema = Sema()
    
    if sema.args.exp_dir == "output/runs/":
        sema.args.exp_dir =  "src/" +  sema.args.exp_dir + str(sema.current_exp_dir) + "/"
        sema.args.binaries = sema.args.exp_dir
    
    sema.tool_scdg.save_conf(sema.args)
    sema.tool_classifier.save_conf(sema.args)
    
    sema.tool_scdg.start_scdg(sema.args)
    
    sema.tool_classifier.init(exp_dir=sema.args.exp_dir)
    sema.tool_classifier.train()

    if sema.tool_classifier.mode == "classification":
        sema.tool_classifier.classify()
    else:
        sema.tool_classifier.detect()

    elapsed_time = time.time() - sema.start_time
    sema.log.info("Total execution time: " + str(elapsed_time))

    if sema.args.train: # TODO
        args_res = {}
        if sema.tool_classifier.classifier_name == "gspan":
            args_res["target"] = sema.mode
        sema.log.info(sema.tool_classifier.classifier.get_stat_classifier(**args_res))

if __name__ == "__main__":
    main()
