from ToolChainClassifier.ToolChainClassifier import ToolChainClassifier
from ToolChainLearning.ToolChainLearning import ToolChainLearning
from ToolChainSCDG.ToolChainSCDG import ToolChainSCDG
from helper.ArgumentParserTC import ArgumentParserTC


class ToolChain:
    def __init__(self):
        args_parser = ArgumentParserTC(self.toolc)
        args, nameFile, expl_method = args_parser.parse_arguments()
        self.toolc = ToolChainSCDG(
            print_sm_step=True, print_syscall=True, debug_error=True, debug_string=True
        )
        self.toolc.build_scdg(args, nameFile, expl_method)
        self.toolm = ToolChainLearning()  # TODO
        self.toolmc = ToolChainClassifier()  # TODO


def main():
    tc = ToolChain()


if __name__ == "__main__":
    main()
