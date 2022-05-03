import argparse
from ToolChainSCDG.helper.ArgumentParserSCDG import ArgumentParserSCDG
from ToolChainClassifier.helper.ArgumentParserClassifier import ArgumentParserClassifier

class ArgumentParserFL:
    # TODO add logs
    def __init__(self,tcw,tcc):        
        self.tool_scdg = tcw
        self.args_parser_scdg = ArgumentParserSCDG(tcw)
        self.tool_classifier = tcc
        self.args_parser_class = ArgumentParserClassifier(tcc)
        self.parser = argparse.ArgumentParser(conflict_handler='resolve',
                                parents=[self.args_parser_scdg.parser,self.args_parser_class.parser]) 
        self.group = self.parser.add_argument_group('Federated learning module arguments')
        self.group.add_argument(
            '--run_name', 
            help='Name for the experiments',
            type=str, 
            default=""
        )
        self.group.add_argument(
            '--nrounds', 
            help='Number of rounds for training',
            type=int, 
            default=5
        )
        self.group.add_argument(
            '--sround', 
            help='Restart from sround',
            type=int, 
            default=0
        )
        self.group.add_argument(
            '--nparts', 
            help='number of partitions',
            type=int,
            default=3
        )
        self.group.add_argument('--FLRtrain', 
            help='FL train rotate',
            action='store_true'
        )
        self.group.add_argument(
            '--smodel', 
            type=int,
            help='Share model type, 1 partly aggregation and 0 fully aggregation, default smodel=0',
            default=0
        )
        self.group.add_argument('--demonstration', 
            help='If set, use specific dataset for each client (3) to simulate different dataset in clients, else use the same input folder dataset for all clients (default: False)',
            action='store_true'
        )
        self.group.add_argument('--no_scdg_create', 
            help='Skip SCDGs create phase (default: False)',
            action='store_true'
        )
        self.group.add_argument('--hostnames', 
                            nargs='+',
                            help='hostnames for celery clients'
        )
        
    def parse_arguments(self, allow_unk=False):
        args = None
        if not allow_unk:
            args = self.parser.parse_args() 
        else:
            args, unknown = self.parser.parse_known_args()
        return args
