
from ToolChainSCDG.helper.ArgumentParserSCDG import ArgumentParserSCDG
from ToolChainClassifier.helper.ArgumentParserClassifier import ArgumentParserClassifier


class ArgumentParserTC:

    def __init__(self,tcw,tcc):
        self.tcw = tcw
        self.args_parser_scdg = ArgumentParserSCDG(tcw)
        
        self.tcc = tcc
        self.args_parser_class = ArgumentParserClassifier(tcc)