
import argparse
from ToolChainSCDG.helper.ArgumentParserSCDG import ArgumentParserSCDG
from ToolChainClassifier.helper.ArgumentParserClassifier import ArgumentParserClassifier


class ArgumentParserTC:

    def __init__(self,tcw,tcc):
        self.parser = argparse.ArgumentParser(description='pipeline arguments', add_help=False, formatter_class=argparse.RawTextHelpFormatter)
        self.parser.add_argument("-h","--help",action="help",
            help=
            """
------------------ \n
SCDG tool options: \n
------------------ \n
\n
positional arguments: \n
  binary                Name of the binary to analyze \n
\n
optional arguments: \n
  -h, --help            show this help message and exit \n
  --method METHOD       Method used for the analysis among (DFS,BFS,CBFS) (default : DFS) \n
  --n_args N_ARGS       Number of symbolic arguments given to the binary (default : 0) \n
  --timeout TIMEOUT     Timeout in seconds before ending extraction (default : 600) \n
  --symb_loop SYMB_LOOP \n
                        Number of iteration allowed for a symbolic loop (default : 3) \n
  --conc_loop CONC_LOOP \n
                        Number of symbolic arguments given to the binary (default : 1024) \n
  --simul_state SIMUL_STATE \n
                        Number of simultaneous states we explore with simulation manager (default : 5) \n
  --limit_pause LIMIT_PAUSE \n
                        Number of states allowed in pause stash (default : 200) \n
  --max_step MAX_STEP   Maximum number of steps allowed for a state (default : 50 000) \n
  --max_deadend MAX_DEADEND \n
                        Number of deadended state required to stop (default : 600) \n
  --min_size MIN_SIZE   Minimum size required for a trace to be used in SCDG (default : 3) \n
  --not_resolv_string   Do we try to resolv references of string (default : False) \n
  --disjoint_union      Do we merge traces or use disjoint union ? (default : merge) \n
  --not_comp_args       Do we compare arguments to add new nodes when building graph ? (default : comparison enabled) \n
  --not_ignore_zero     Do we ignore zero when building graph ? (default : Discard zero) \n
  --dir DIR             Directory to save outputs graph for gspan (default : output/) \n
  --exp_dir EXP_DIR     Directory to save SCDG extracted (default : output/save-SCDG/) \n
  --discard_SCDG        Do not keep intermediate SCDG in file (default : True) \n
  --eval_time           Keep intermediate SCDG in file (default : False) \n
  --verbose             Verbose output during calls extraction (default : False) \n
  --debug_error         Debug error states (default : False) \n
  --format_out FORMAT_OUT \n
                        Format to save graph output : gs or json (Default: gs) \n
  --packed              Is the binary packed ? (default : False) \n
  --unpack_method UNPACK_METHOD \n
                        unpack with Symbion (linux only | todo) or with unipacker (windows only) [symbion|unipacker] True if --packed is set with symbion as \n
                        default \n
  --concrete_target_is_local \n
                        Use a local GDB server instead of using cuckoo (default : False) \n
  --familly FAMILLY     Use a local GDB server instead of using cuckoo (default : False) \n
  --hostnames HOSTNAMES [HOSTNAMES ...] \n
                        hostnames for celery clients \n
\n
---------------------------- \n
Classification tool options: \n
---------------------------- \n
\n 
positional arguments: \n
  binary                Name of the binary to analyze (Default: output/save-SCDG/, only that for ToolChain) \n
\n
optional arguments: \n
  -h, --help            show this help message and exit \n
  --classifier CLASSIFIER
                        Classifier used for the analysis among (gspan,inria,wl,dl) (default : wl) \n
  --threshold THRESHOLD \n
                        Threshold used for the classifier [0..1] (default : 0.45) \n
  --support SUPPORT     Support used for the gpsan classifier [0..1] (default : 0.75) \n
  --smodel SMODEL       Share model type, 1 partly aggregation and 0 fully aggregation, default smodel=0 \n
  --nthread NTHREAD     Number of thread used (default: max) \n
  --biggest_subgraph BIGGEST_SUBGRAPH \n
                        Number of thread used (default: max) \n
  --ctimeout CTIMEOUT   Timeout for gspan classifier (default : 3sec) \n
  --families FAMILIES [FAMILIES ...] \n
                        Families considered (default : ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2 \n
                        p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']) \n
  --mode MODE           detection = binary decision cleanware vs malware (default) OR classification = malware family \n
  --epoch EPOCH         Only for deep learning model: number of epoch (default: 5) Always 1 for FL model \n
  --data_scale DATA_SCALE \n
                        Only for deep learning model: data scale value (default: 0.9) \n
  --vector_size VECTOR_SIZE \n
                        Only for deep learning model: Size of the vector used (default: 4) \n
  --batch_size BATCH_SIZE \n
                        Only for deep learning model: Batch size for the model (default: 1) \n
            """) # TODO better
        args, unknown = self.parser.parse_known_args()
        self.tcw = tcw
        self.args_parser_scdg = ArgumentParserSCDG(tcw)
        
        self.tcc = tcc
        self.args_parser_class = ArgumentParserClassifier(tcc)