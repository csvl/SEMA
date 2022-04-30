
import argparse
from ToolChainSCDG.helper.ArgumentParserSCDG import ArgumentParserSCDG
from ToolChainClassifier.helper.ArgumentParserClassifier import ArgumentParserClassifier


class ArgumentParserTC:

    def __init__(self,tcw,tcc):        
        self.tool_scdg = tcw
        self.args_parser_scdg = ArgumentParserSCDG(tcw)
        self.tool_classifier = tcc
        self.args_parser_class = ArgumentParserClassifier(tcc)
        self.parser = argparse.ArgumentParser(conflict_handler='resolve',
                                parents=[self.args_parser_scdg.parser,self.args_parser_class.parser]) #,self.args_parser_class.parser
    
    # TODO conflict with --exp_dir and binaries arguments 
    def parse_arguments(self, allow_unk=False):
        args = None
        if not allow_unk:
            args = self.parser.parse_args() 
        else:
            args, unknown = self.parser.parse_known_args()
        return args