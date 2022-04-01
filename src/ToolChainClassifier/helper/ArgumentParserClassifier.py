

import argparse
import sys
import multiprocessing

class ArgumentParserClassifier:
    # TODO add logs
    def __init__(self, tcw):
        self.tcw = tcw
    
    def parse_arguments(self, allow_unk=False):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--classifier",
            help="Classifier used for the analysis among (gspan,inria,wl,dl) (default : wl)",
        )
        parser.add_argument(
            "--threshold",
            help="Threshold used for the classifier [0..1] (default : 0.45)",
            type=float,
            default=0.45,
        )
        parser.add_argument(
            "--support",
            help="Support used for the gpsan classifier [0..1] (default : 0.75)",
            type=float,
            default=0.75,
        )
        parser.add_argument(
            "--nthread",
            help="Number of thread used (default: max)",
            type=int,
            default=multiprocessing.cpu_count(),
        )
        parser.add_argument(
            "--biggest_subgraph",
            help="Number of thread used (default: max)",
            type=int,
            default=5,
        )
        parser.add_argument(
            "--ctimeout",
            help="Timeout for gspan classifier (default : 3sec)",
            type=int,
            default=3,
        )
        parser.add_argument(
            "--families",
            nargs='+',
            help="Families considered (default : ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT'])",
        )
        parser.add_argument(
            "--mode",
            help="detection = binary decision cleanware vs malware (default) OR classification = malware family ",
        )
        parser.add_argument(
            "--epoch",
            help="Only for deep learning model: number of epoch (default: 5)",
            type=int,
            default=5,
        )
        parser.add_argument(
            "--data_scale",
            help="Only for deep learning model: data scale value (default: 0.9)",
            type=float,
            default=0.9,
        )
        parser.add_argument(
            "--vector_size",
            help="Only for deep learning model: Size of the vector used (default: 4)",
            type=int,
            default=4,
        )
        parser.add_argument(
            "--batch_size",
            help="Only for deep learning model: Batch size for the model (default: 1)",
            type=int,
            default=1,
        )
        
        parser.add_argument("binary", help="Name of the binary to analyze (Default: output/save-SCDG/, only that for ToolChain)")
        args = None
        if not allow_unk:
            args = parser.parse_args()
        else:
            args, unknown = parser.parse_known_args()

        if args.binary and not allow_unk:
            self.tcw.input_path = args.binary
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

        return args
