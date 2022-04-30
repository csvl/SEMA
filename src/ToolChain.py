import os
import time
from re import sub
import logging
import progressbar
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

        self.tool_scdg = ToolChainSCDG(
            print_sm_step=True,
            print_syscall=True,
            debug_error=True,
            debug_string=True,
            print_on=True,
            is_from_tc=True
        )
        
        self.tool_classifier = ToolChainClassifier(parse=False)
        self.args_parser = ArgumentParserTC(self.tool_scdg, self.tool_classifier)
        self.args = self.args_parser.parse_arguments()
        self.tool_classifier.args = self.args
        self.args_parser.args_parser_scdg.update_tool(self.args)
        self.args_parser.args_parser_class.update_tool(self.args)
        self.families = []
        self.args.exp_dir = self.args.binaries
        self.args.dir = self.args.binaries
      
def main():
    tc = ToolChain()
    tc.tool_scdg.start_scdg(tc.args)
    
    tc.tool_classifier.init(exp_dir=tc.args.exp_dir)
    tc.tool_classifier.train()

    if tc.tool_classifier.mode == "classification":
        tc.tool_classifier.classify()
    else:
        tc.tool_classifier.detect()

    elapsed_time = time.time() - tc.start_time
    tc.log.info("Total execution time: " + str(elapsed_time))

    if tc.args.train: # TODO
        args_res = {}
        if tc.tool_classifier.classifier_name == "gspan":
            args_res["target"] = tc.mode
        tc.log.info(tc.tool_classifier.classifier.get_stat_classifier(**args_res))

if __name__ == "__main__":
    main()
