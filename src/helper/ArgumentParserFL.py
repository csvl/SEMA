import argparse

class ArgumentParserFL:
    # TODO add logs
    def __init__(self):
        pass

    def parse_arguments(self,allow_unk=True):
        parser = argparse.ArgumentParser(description='pipeline arguments')
        parser.add_argument('--runname', help='run name in temp, each partition folder is the form of <runname>_part0,..')
        parser.add_argument('--train', help='Train',action='store_true')
        parser.add_argument('--nepochs', type=int,help='n_epochs',default =1)
        parser.add_argument('--sepoch', type=int,help='Restart training from sepoch, default sepoch=1',default =1)
        
        parser.add_argument('--FLtrain', help='FL train',action='store_true')
        parser.add_argument('--nrounds', help='Number of rounds for training',type=int, default= 1)
        parser.add_argument('--sround', help='Restart from sround',type=int, default= 0)
        parser.add_argument('--smodel', type=int,help='Share model type, 1 partly aggregation and 0 fully aggregation, default smodel=0',default =0)
        
        parser.add_argument('--nparts', help='number of partitions',type=int,default= 3)

        parser.add_argument('--FLRtrain', help='FL train rotate',action='store_true')

        parser.add_argument('--test', help='Analysis results',action='store_true')
        parser.add_argument('--model', help='the path of model file')
        parser.add_argument('--db', help='the path of data')

        parser.add_argument("binary", help="Name of the binary to analyze (Default: output/save-SCDG/, only that for ToolChain)")
        args = None
        if not allow_unk:
            args = parser.parse_args()
        else:
            args, unknown = parser.parse_known_args()
        
        return args, unknown