import argparse

class ArgumentParserFL:
    # TODO add logs
    def __init__(self):
        pass

    def parse_arguments(self):
        parser = argparse.ArgumentParser()
        # TODO merge with parser of Classifier
        parser.add_argument('--train', 
            help='Train',
            action='store_true'
        )
        parser.add_argument('--sepoch', 
            type=int,
            help='Restart training from sepoch, default sepoch=1',
            default=1
        )
        parser.add_argument('--nrounds', 
            help='Number of rounds for training',
            type=int, 
            default=5
        )
        parser.add_argument('--sround', 
            help='Restart from sround',
            type=int, 
            default=0
        )
        parser.add_argument('--smodel', 
            type=int,
            help='Share model type, 1 partly aggregation and 0 fully aggregation, default smodel=0',
            default=0
        )
        parser.add_argument('--nparts', 
            help='number of partitions',
            type=int,
            default=3
        )
        parser.add_argument('--FLRtrain', 
            help='FL train rotate',
            action='store_true'
        )
        parser.add_argument('--demonstration', 
            help='If set, use specific dataset for each client (3) to simulate different dataset in clients, else use the same input folder dataset for all clients',
            action='store_true'
        )
        parser.add_argument('--hostnames', 
                            nargs='+',
                            help='hostnames for celery clients'
        )
        parser.add_argument("binary", 
                            help="Name of the binary to analyze (Default: output/save-SCDG/, only that for ToolChain)")
        args = None
        args, unknown = parser.parse_known_args()
        
        return args