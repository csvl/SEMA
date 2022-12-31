

import argparse
import sys
import multiprocessing

class ArgumentParserClassifier:
    # TODO add logs
    def __init__(self, tcw):
        self.parser = argparse.ArgumentParser(description='Classification module arguments')
        self.group_global_class = self.parser.add_argument_group("Global classifiers parameters")
        self.group_global_class.add_argument(
            "--threshold",
            help="Threshold used for the classifier [0..1] (default : 0.45)",
            type=float,
            default=0.45,
        )
        
        self.group_gspan = self.parser.add_argument_group('Gspan options') # TODO add description
        self.group_gspan.add_argument(
            "--biggest_subgraph",
            help="Biggest subgraph consider for Gspan (default: 5)",
            type=int,
            default=5,
        )
        self.group_gspan.add_argument(
            "--support",
            help="Support used for the gpsan classifier [0..1] (default : 0.75)",
            type=float,
            default=0.75,
        )
        self.group_gspan.add_argument(
            "--ctimeout",
            help="Timeout for gspan classifier (default : 3sec)",
            type=int,
            default=3,
        )
        
        self.group_dl = self.parser.add_argument_group('Deep Learning options')
        self.group_dl.add_argument(
            "--epoch",
            help="Only for deep learning model: number of epoch (default: 5)\n Always 1 for FL model",
            type=int,
            default=5,
        )
        self.group_dl.add_argument(
            "--sepoch",
            help="Only for deep learning model: starting epoch (default: 1)\n",
            type=int,
            default=1,
        )
        self.group_dl.add_argument(
            "--data_scale",
            help="Only for deep learning model: data scale value (default: 0.9)",
            type=float,
            default=0.9,
        )
        self.group_dl.add_argument(
            "--vector_size",
            help="Only for deep learning model: Size of the vector used (default: 4)",
            type=int,
            default=4,
        )                            
        self.group_dl.add_argument(
            "--batch_size",
            help="Only for deep learning model: Batch size for the model (default: 1)",
            type=int,
            default=1,
        )

        self.group_global_expl = self.parser.add_mutually_exclusive_group(required=True)
        self.group_global_expl.title = 'Operation mode'
        self.group_global_expl.add_argument(
            "--classification",
            help="By malware family",
            action="store_false",
            
        )
        self.group_global_expl.add_argument(
            "--detection",
            help="Cleanware vs Malware",
            action="store_true",
            
        )
        
        
        self.group_cl = self.parser.add_mutually_exclusive_group(required=True)
        self.group_cl.title = 'Classifier used'
        self.group_cl.add_argument(
            "--wl",
            help="TODO",
            action="store_false",
            
        )
        self.group_cl.add_argument(
            "--inria",
            help="TODO",
            action="store_true",
            
        )
        self.group_cl.add_argument(
            "--dl",
            help="TODO",
            action="store_true",
            
        )
        self.group_cl.add_argument(
            "--gspan",
            help="TODOe",
            action="store_true",
            
        )
        
        # TODO dynamic
        self.group_familly = self.parser.add_argument_group('Malware familly')
        self.group_familly.add_argument(
            "--bancteian",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--delf",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--FeakerStealer",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--gandcrab",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--ircbot",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--lamer",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--nitol",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--RedLineStealer",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--sfone",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--sillyp2p",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--simbot",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--Sodinokibi",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--sytro",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--upatre",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--wabot",
            action="store_false",
        )
        self.group_familly.add_argument(
            "--RemcosRAT",
            action="store_false",
        )
        
        
        self.group = self.parser.add_argument_group('Global parameter')
        self.group.add_argument( # TODO 
            "--verbose_classifier",
            help="Verbose output during train/classification  (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--train",
            help="Launch training process, else classify/detect new sample with previously computed model",
            action='store_true'
        )
        self.group.add_argument(
            "--nthread",
            help="Number of thread used (default: max)",
            type=int,
            default=multiprocessing.cpu_count(),
        )
        
        self.group.add_argument("binaries", 
                                default="output/save-SCDG/",
                                help="Name of the folder containing binary'signatures to analyze (Default: output/save-SCDG/, only that for ToolChain)")
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

    def parse_arguments(self, allow_unk=False, args_list=None):
        args = None
        if not allow_unk:
            args = self.parser.parse_args(args_list)
        else:
            args, unknown = self.parser.parse_known_args(args_list)

        return args
