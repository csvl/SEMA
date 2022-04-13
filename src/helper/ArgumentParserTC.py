
import argparse
from ToolChainSCDG.helper.ArgumentParserSCDG import ArgumentParserSCDG
from ToolChainClassifier.helper.ArgumentParserClassifier import ArgumentParserClassifier


class ArgumentParserTC:

    def __init__(self,tcw,tcc):
        self.parser = argparse.ArgumentParser(description='pipeline arguments', add_help=False, formatter_class=argparse.RawTextHelpFormatter)
        self.parser.add_argument("-h","--help",action="help",default=argparse.SUPPRESS,
            help=
            """
------------------ 
SCDG tool options: 
------------------ 

positional arguments: 
  binary                Name of the binary to analyze 

optional arguments: 
  -h, --help            show this help message and exit 
  --method METHOD       Method used for the analysis among (DFS,BFS,CBFS) (default : DFS) 
  --n_args N_ARGS       Number of symbolic arguments given to the binary (default : 0) 
  --timeout TIMEOUT     Timeout in seconds before ending extraction (default : 600) 
  --symb_loop SYMB_LOOP 
                        Number of iteration allowed for a symbolic loop (default : 3) 
  --conc_loop CONC_LOOP 
                        Number of symbolic arguments given to the binary (default : 1024) 
  --simul_state SIMUL_STATE 
                        Number of simultaneous states we explore with simulation manager (default : 5) 
  --limit_pause LIMIT_PAUSE 
                        Number of states allowed in pause stash (default : 200) 
  --max_step MAX_STEP   Maximum number of steps allowed for a state (default : 50 000) 
  --max_deadend MAX_DEADEND 
                        Number of deadended state required to stop (default : 600) 
  --min_size MIN_SIZE   Minimum size required for a trace to be used in SCDG (default : 3) 
  --not_resolv_string   Do we try to resolv references of string (default : False) 
  --disjoint_union      Do we merge traces or use disjoint union ? (default : merge) 
  --not_comp_args       Do we compare arguments to add new nodes when building graph ? (default : comparison enabled) 
  --not_ignore_zero     Do we ignore zero when building graph ? (default : Discard zero) 
  --dir DIR             Directory to save outputs graph for gspan (default : output/) 
  --exp_dir EXP_DIR     Directory to save SCDG extracted (default : output/save-SCDG/) 
  --discard_SCDG        Do not keep intermediate SCDG in file (default : True) 
  --eval_time           Keep intermediate SCDG in file (default : False) 
  --verbose             Verbose output during calls extraction (default : False) 
  --debug_error         Debug error states (default : False) 
  --format_out FORMAT_OUT 
                        Format to save graph output : gs or json (Default: gs) 
  --packed              Is the binary packed ? (default : False) 
  --unpack_method UNPACK_METHOD 
                        unpack with Symbion (linux only | todo) or with unipacker (windows only) [symbion|unipacker] True if --packed is set with symbion as 
                        default 
  --concrete_target_is_local 
                        Use a local GDB server instead of using cuckoo (default : False) 
  --familly FAMILLY     Use a local GDB server instead of using cuckoo (default : False) 
  --hostnames HOSTNAMES [HOSTNAMES ...] 
                        hostnames for celery clients 

---------------------------- 
Classification tool options: 
---------------------------- 
 
positional arguments: 
  binary                Name of the binary to analyze (Default: output/save-SCDG/, only that for ToolChain) 

optional arguments: 
  -h, --help            show this help message and exit 
  --classifier CLASSIFIER
                        Classifier used for the analysis among (gspan,inria,wl,dl) (default : wl) 
  --threshold THRESHOLD 
                        Threshold used for the classifier [0..1] (default : 0.45) 
  --support SUPPORT     Support used for the gpsan classifier [0..1] (default : 0.75) 
  --smodel SMODEL       Share model type, 1 partly aggregation and 0 fully aggregation, default smodel=0 
  --nthread NTHREAD     Number of thread used (default: max) 
  --biggest_subgraph BIGGEST_SUBGRAPH 
                        Number of thread used (default: max) 
  --ctimeout CTIMEOUT   Timeout for gspan classifier (default : 3sec) 
  --families FAMILIES [FAMILIES ...] 
                        Families considered (default : ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2 
                        p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT']) 
  --mode MODE           detection = binary decision cleanware vs malware (default) OR classification = malware family 
  --epoch EPOCH         Only for deep learning model: number of epoch (default: 5) Always 1 for FL model 
  --data_scale DATA_SCALE 
                        Only for deep learning model: data scale value (default: 0.9) 
  --vector_size VECTOR_SIZE 
                        Only for deep learning model: Size of the vector used (default: 4) 
  --batch_size BATCH_SIZE 
                        Only for deep learning model: Batch size for the model (default: 1) 
            """) # TODO better
        args, unknown = self.parser.parse_known_args()
        self.tcw = tcw
        self.args_parser_scdg = ArgumentParserSCDG(tcw)
        
        self.tcc = tcc
        self.args_parser_class = ArgumentParserClassifier(tcc)