

import argparse
import sys
import multiprocessing

class ArgumentParserClassifier:
    # TODO add logs
    def __init__(self, tcw):
        self.parser = argparse.ArgumentParser(description='Classification module arguments')
        self.group = self.parser.add_argument_group('Classification module arguments')
        self.group.add_argument(
            "--train",
            help="Launch training process, else classify/detect new sample with previously computed model",
            action='store_true'
        )
        self.group.add_argument(
            "--classifier",
            help="Classifier used for the analysis among (gspan,inria,wl,dl) (default : wl)",
        )
        self.group.add_argument(
            "--threshold",
            help="Threshold used for the classifier [0..1] (default : 0.45)",
            type=float,
            default=0.45,
        )
        self.parser.add_argument(
            "--biggest_subgraph",
            help="Biggest subgraph consider for Gspan (default: 5)",
            type=int,
            default=5,
        )
        self.group.add_argument(
            "--support",
            help="Support used for the gpsan classifier [0..1] (default : 0.75)",
            type=float,
            default=0.75,
        )
        self.group.add_argument(
            "--nthread",
            help="Number of thread used (default: max)",
            type=int,
            default=multiprocessing.cpu_count(),
        )
        self.group.add_argument( # TODO 
            "--verbose_classifier",
            help="Verbose output during train/classification  (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--ctimeout",
            help="Timeout for gspan classifier (default : 3sec)",
            type=int,
            default=3,
        )
        self.group.add_argument(
            "--families",
            nargs='+',
            help="Families considered (default : ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT'])",
        )
        self.group.add_argument(
            "--mode",
            help="detection = binary decision cleanware vs malware (default) OR classification = malware family ",
        )
        self.group.add_argument(
            "--epoch",
            help="Only for deep learning model: number of epoch (default: 5)\n Always 1 for FL model",
            type=int,
            default=5,
        )
#        self.group.add_argument(
#            "--sepoch",
#            help="Only for deep learning model: starting epoch (default: 1)\n",
#            type=int,
#            default=1,
#        )
#        self.group.add_argument(
#            "--data_scale",
#            help="Only for deep learning model: data scale value (default: 0.9)",
#            type=float,
#            default=0.9,
#        )
#        self.group.add_argument(
#            "--vector_size",
#            help="Only for deep learning model: Size of the vector used (default: 4)",
#            type=int,
#            default=4,
#        )                            
#        self.group.add_argument(
#            "--batch_size",
#            help="Only for deep learning model: Batch size for the model (default: 1)",
#            type=int,
#            default=1,
#        )
        self.group.add_argument("binaries", help="Name of the folder containing binary'signatures to analyze (Default: output/save-SCDG/, only that for ToolChain)")
        self.tcw = tcw

    def update_tool(self, args):
        if args.binaries: # and not allow_unk
            self.tcw.input_path = args.binaries
        else:
            self.tcw.input_path = None
        sys.setrecursionlimit(2000)
        if args.classifier:
            class_method = args.classifier
            if class_method.lower() not in ["gspan","inria","wl","dl"]:
                self.tcw.classifier_name = "wl"
            else:
                self.tcw.classifier_name = class_method
        else:
            self.tcw.classifier_name = "wl"

        if args.threshold:
            self.tcw.threshold = args.threshold

        if args.mode:
            self.tcw.mode = args.mode

    def parse_arguments(self, allow_unk=False):
        args = None
        if not allow_unk:
            args = self.parser.parse_args()
        else:
            args, unknown = self.parser.parse_known_args()

        return args
