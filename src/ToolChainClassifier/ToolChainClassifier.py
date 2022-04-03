import logging
import os
import time

try:
    from classifier.GM.GSpanClassifier import GSpanClassifier
    from helper.ArgumentParserClassifier import ArgumentParserClassifier
    from classifier.SVM.SVMInriaClassifier import SVMInriaClassifier
    from classifier.SVM.SVMWLClassifier import SVMWLClassifier
    from clogging.CustomFormatter import CustomFormatter
except:
    from .classifier.GM.GSpanClassifier import GSpanClassifier
    from .helper.ArgumentParserClassifier import ArgumentParserClassifier
    from .classifier.SVM.SVMInriaClassifier import SVMInriaClassifier
    from .classifier.SVM.SVMWLClassifier import SVMWLClassifier
    from .clogging.CustomFormatter import CustomFormatter


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class ToolChainClassifier:
    def __init__(self, classifier_name="wl"):
        self.classifier = None
        self.input_path = None
        self.mode = "classification"
        self.classifier_name = classifier_name
        self.start_time = time.time()
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("ToolChainClassifier")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False

    def init_classifer(self,args,families=['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']):
        if self.classifier_name == "gspan":
            self.classifier = GSpanClassifier(path=ROOT_DIR,threshold=args.threshold,support=args.support,timeout=args.ctimeout,thread=args.nthread,biggest_subgraphs=args.biggest_subgraph)
        elif self.classifier_name == "inria": 
            self.classifier = SVMInriaClassifier(path=ROOT_DIR,threshold=args.threshold,families=families)
        elif self.classifier_name == "wl": 
            self.classifier = SVMWLClassifier(path=ROOT_DIR,threshold=args.threshold,families=families,epoch=args.epoch)
        elif self.classifier_name == "dl": # not working with pypy
            try:
                from classifier.DL.DLTrainerClassifier import DLTrainerClassifier
            except:
                from .classifier.DL.DLTrainerClassifier import DLTrainerClassifier
            self.classifier = DLTrainerClassifier(path=ROOT_DIR,threshold=args.threshold)
        else:
            self.log.info("Error: Unrecognize classifer (gspan|inria|wl|dl)")
            exit(-1)    
     
def main():
    tc = ToolChainClassifier()
    args_parser = ArgumentParserClassifier(tc)
    args = args_parser.parse_arguments()

    if tc.input_path is None:
        input_path = ROOT_DIR.replace("ToolChainClassifier","output/save-SCDG") # todo add args
    else:
        input_path = tc.input_path

    if args.families:
        tc.init_classifer(args=args,families=args.families)
    else:
        families = []
        last_familiy = "unknown"
        if os.path.isdir(input_path):
            subfolder = [os.path.join(input_path, f) for f in os.listdir(input_path) if os.path.isdir(os.path.join(input_path, f))]
            tc.log.info(subfolder)
            for folder in subfolder:
                last_familiy = folder.split("/")[-1]
                families.append(str(last_familiy))
        tc.init_classifer(args=args,families=families)
    
    if tc.input_path is None:
        tc.classifier.train(input_path)
    else:
        tc.classifier.train(tc.input_path)
    
    elapsed_time = time.time() - tc.start_time
    tc.log.info("Total training time: " + str(elapsed_time))

    if tc.mode == "classification":
        tc.classifier.classify()
    else:
        tc.classifier.detection()

    elapsed_time = time.time() - tc.start_time
    tc.log.info("Total "+ tc.mode +" time: " + str(elapsed_time))

    if tc.classifer_name == "gspan":
        tc.classifier.get_stat_classifier(target=tc.mode)
    else:
        tc.classifier.get_stat_classifier()


if __name__ == "__main__":
    main()